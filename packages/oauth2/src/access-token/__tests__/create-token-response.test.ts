import { HashAlgorithm } from "@openid4vc/oauth2";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  CreateAccessTokenResponseOptions,
  createAccessTokenResponse,
} from "../create-token-response";

const mockCallbacks = {
  generateRandom: vi.fn(),
  hash: vi.fn(),
  signJwt: vi.fn(),
};

const mockSigner = {
  alg: "ES256",
  method: "jwk" as const,
  publicJwk: {
    crv: "P-256",
    kid: "test-kid",
    kty: "EC",
    x: "test-x-value",
    y: "test-y-value",
  },
};

const fixedNow = new Date("2024-01-01T00:00:00Z");

const baseOptions: CreateAccessTokenResponseOptions = {
  audience: "https://wallet-provider.example.com",
  authorizationServer: "https://as.example.com",
  callbacks: mockCallbacks,
  clientId: "wallet-client-id",
  expiresInSeconds: 300,
  now: fixedNow,
  signer: mockSigner,
  subject: "subject-id",
  tokenType: "Bearer",
};

describe("createAccessTokenResponse", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mockCallbacks.generateRandom.mockResolvedValue(
      new Uint8Array([1, 2, 3, 4]),
    );
    mockCallbacks.hash.mockResolvedValue(new Uint8Array([9, 10, 11, 12]));
    mockCallbacks.signJwt.mockResolvedValue({
      jwt: "signed-access-token-jwt",
      signerJwk: mockSigner.publicJwk,
    });
  });

  it("creates a full DPoP-bound access token response", async () => {
    const result = await createAccessTokenResponse({
      ...baseOptions,
      additionalPayload: {
        authorization_details: [
          {
            credential_configuration_id: "pid-sd-jwt",
            type: "openid_credential",
          },
        ],
      },
      dpop: {
        jwk: mockSigner.publicJwk,
      },
      nbf: 1704067200,
      refreshToken: "refresh-token-value",
      tokenType: "DPoP",
    });

    expect(result).toEqual({
      access_token: "signed-access-token-jwt",
      authorization_details: [
        {
          credential_configuration_id: "pid-sd-jwt",
          type: "openid_credential",
        },
      ],
      expires_in: 300,
      refresh_token: "refresh-token-value",
      token_type: "DPoP",
    });
  });

  it("builds JWT header and payload with expected mandatory claims", async () => {
    await createAccessTokenResponse(baseOptions);

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: "ES256",
        jwk: mockSigner.publicJwk,
        typ: "at+jwt",
      },
      payload: expect.objectContaining({
        aud: "https://wallet-provider.example.com",
        client_id: "wallet-client-id",
        exp: 1704067500,
        iat: 1704067200,
        iss: "https://as.example.com",
        jti: "AQIDBA",
        sub: "subject-id",
      }),
    });
  });

  it("adds cnf.jkt when dpop is provided", async () => {
    await createAccessTokenResponse({
      ...baseOptions,
      dpop: {
        jwk: mockSigner.publicJwk,
      },
      tokenType: "DPoP",
    });

    expect(mockCallbacks.hash).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      HashAlgorithm.Sha256,
    );
    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        cnf: {
          jkt: "CQoLDA",
        },
      }),
    });
  });

  it("omits optional fields when not provided", async () => {
    const result = await createAccessTokenResponse(baseOptions);

    expect(result).toEqual({
      access_token: "signed-access-token-jwt",
      expires_in: 300,
      token_type: "Bearer",
    });

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.not.objectContaining({
        cnf: expect.anything(),
        nbf: expect.anything(),
        scope: expect.anything(),
      }),
    });
  });

  it("uses provided now for deterministic iat and exp", async () => {
    await createAccessTokenResponse({
      ...baseOptions,
      expiresInSeconds: 3600,
      now: new Date("2024-05-05T10:00:00Z"),
    });

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        exp: 1714906800,
        iat: 1714903200,
      }),
    });
  });

  it("propagates additionalPayload to payload and response envelope", async () => {
    const result = await createAccessTokenResponse({
      ...baseOptions,
      additionalPayload: {
        custom_claim: "custom-value",
      },
    });

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        custom_claim: "custom-value",
      }),
    });
    expect(result).toEqual(
      expect.objectContaining({
        custom_claim: "custom-value",
      }),
    );
  });
});
