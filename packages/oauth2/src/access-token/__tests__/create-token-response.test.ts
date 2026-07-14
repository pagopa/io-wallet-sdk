import { HashAlgorithm } from "@pagopa/io-wallet-utils";
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

const RT_JTI_BYTES = new Uint8Array([
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x0e, 0x0f, 0x10,
]);

// bytes[6] = 0x07 -> (0x07 & 0x0f) | 0x40 = 0x47 (version 4)
// bytes[8] = 0x09 -> (0x09 & 0x3f) | 0x80 = 0x89 (variant 10)
const RT_EXPECTED_JTI = "01020304-0506-4708-890a-0b0c0d0e0f10";

interface SignJwtCallArgs {
  header: { typ?: string };
  payload: Record<string, unknown>;
}

function findSignJwtCallByTyp(typ: string): SignJwtCallArgs {
  const call = mockCallbacks.signJwt.mock.calls.find(
    (callArgs) => (callArgs[1] as SignJwtCallArgs).header.typ === typ,
  );
  if (!call) {
    throw new Error(`No signJwt call found with header.typ = ${typ}`);
  }
  return call[1] as SignJwtCallArgs;
}

function setupMockCallbacks(): void {
  vi.restoreAllMocks();
  mockCallbacks.generateRandom.mockImplementation(async (byteLength: number) =>
    byteLength === 16 ? RT_JTI_BYTES : new Uint8Array([1, 2, 3, 4]),
  );
  mockCallbacks.hash.mockResolvedValue(new Uint8Array([9, 10, 11, 12]));
  mockCallbacks.signJwt.mockImplementation(
    async (_signer: unknown, jwt: { header: { typ?: string } }) => ({
      jwt:
        jwt.header.typ === "rt+jwt"
          ? "signed-refresh-token-jwt"
          : "signed-access-token-jwt",
      signerJwk: mockSigner.publicJwk,
    }),
  );
}

describe("createAccessTokenResponse", () => {
  beforeEach(() => {
    setupMockCallbacks();
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
        jti: RT_EXPECTED_JTI,
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

  it("throws when tokenType is DPoP but dpop option is missing", async () => {
    await expect(
      createAccessTokenResponse({
        ...baseOptions,
        tokenType: "DPoP",
      }),
    ).rejects.toThrow(
      "token_type is DPoP but dpop option is not provided. Please provide a DPoP public key in the dpop option or set tokenType to 'Bearer'.",
    );
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

  it("rejects the removed refreshToken option at compile time", () => {
    const invalidOptions: CreateAccessTokenResponseOptions = {
      ...baseOptions,
      // @ts-expect-error refreshToken was removed in favor of refreshTokenExpiresInSeconds
      refreshToken: "refresh-token-value",
    };

    expect(invalidOptions).toBeDefined();
  });
});

describe("createAccessTokenResponse - Refresh Token issuance", () => {
  const dpopOptions: CreateAccessTokenResponseOptions = {
    ...baseOptions,
    dpop: {
      jwk: mockSigner.publicJwk,
    },
    refreshTokenExpiresInSeconds: 3600,
    tokenType: "DPoP",
  };

  beforeEach(() => {
    setupMockCallbacks();
  });

  it("issues a signed DPoP-bound Refresh Token JWT as refresh_token", async () => {
    const result = await createAccessTokenResponse(dpopOptions);

    expect(result).toEqual(
      expect.objectContaining({
        refresh_token: "signed-refresh-token-jwt",
      }),
    );
  });

  it("builds the Refresh Token header with typ=rt+jwt, alg, and kid", async () => {
    await createAccessTokenResponse(dpopOptions);

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: "ES256",
        kid: "test-kid",
        typ: "rt+jwt",
      },
      payload: expect.any(Object),
    });
  });

  it("resolves kid from signer.kid when present, overriding publicJwk.kid", async () => {
    const signerWithKid = {
      ...mockSigner,
      kid: "signer-level-kid",
    };

    await createAccessTokenResponse({
      ...dpopOptions,
      signer: signerWithKid,
    });

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(
      signerWithKid,
      expect.objectContaining({
        header: expect.objectContaining({ kid: "signer-level-kid" }),
      }),
    );
  });

  it("builds the Refresh Token payload with every mandatory claim", async () => {
    await createAccessTokenResponse(dpopOptions);

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: {
        aud: "https://as.example.com",
        client_id: "wallet-client-id",
        cnf: { jkt: "CQoLDA" },
        exp: 1704070800,
        iat: 1704067200,
        iss: "https://as.example.com",
        jti: RT_EXPECTED_JTI,
        nbf: 1704067500,
        sub: "subject-id",
      },
    });
  });

  it("sets Refresh Token nbf equal to the Access Token exp", async () => {
    await createAccessTokenResponse(dpopOptions);

    const accessTokenCall = findSignJwtCallByTyp("at+jwt");
    const refreshTokenCall = findSignJwtCallByTyp("rt+jwt");

    expect(refreshTokenCall.payload.nbf).toBe(accessTokenCall.payload.exp);
  });

  it("binds both Access Token and Refresh Token to the same DPoP key via cnf.jkt", async () => {
    await createAccessTokenResponse(dpopOptions);

    const accessTokenCall = findSignJwtCallByTyp("at+jwt");
    const refreshTokenCall = findSignJwtCallByTyp("rt+jwt");

    expect((refreshTokenCall.payload.cnf as { jkt: string }).jkt).toBe(
      (accessTokenCall.payload.cnf as { jkt: string }).jkt,
    );
  });

  it("generates a canonical UUID v4 jti from 16 random bytes", async () => {
    await createAccessTokenResponse(dpopOptions);

    expect(mockCallbacks.generateRandom).toHaveBeenCalledWith(16);
    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({ jti: RT_EXPECTED_JTI }),
    });
  });

  it("omits refresh_token when refreshTokenExpiresInSeconds is not provided", async () => {
    const result = await createAccessTokenResponse(baseOptions);

    expect(result.refresh_token).toBeUndefined();
    expect(mockCallbacks.signJwt).toHaveBeenCalledTimes(1);
  });

  it("throws when refreshTokenExpiresInSeconds does not extend beyond the Access Token lifetime", async () => {
    await expect(
      createAccessTokenResponse({
        ...dpopOptions,
        refreshTokenExpiresInSeconds: 300,
      }),
    ).rejects.toThrow(
      "refreshTokenExpiresInSeconds (300) must be greater than expiresInSeconds (300)",
    );
  });

  it("throws when refreshTokenExpiresInSeconds is zero or negative", async () => {
    await expect(
      createAccessTokenResponse({
        ...dpopOptions,
        refreshTokenExpiresInSeconds: 0,
      }),
    ).rejects.toThrow(
      "refreshTokenExpiresInSeconds (0) must be greater than expiresInSeconds (300)",
    );
  });

  it("throws when refreshTokenExpiresInSeconds is provided but tokenType is not DPoP", async () => {
    await expect(
      createAccessTokenResponse({
        ...baseOptions,
        refreshTokenExpiresInSeconds: 3600,
        tokenType: "Bearer",
      }),
    ).rejects.toThrow(
      "refreshTokenExpiresInSeconds was provided but Refresh Token issuance requires tokenType to be 'DPoP' with a dpop public key.",
    );
  });

  it("throws when the signer has no resolvable kid for the Refresh Token", async () => {
    const signerWithoutKid = {
      alg: "ES256",
      method: "jwk" as const,
      publicJwk: {
        crv: "P-256",
        kty: "EC",
        x: "test-x-value",
        y: "test-y-value",
      },
    };

    await expect(
      createAccessTokenResponse({
        ...dpopOptions,
        dpop: { jwk: signerWithoutKid.publicJwk },
        signer: signerWithoutKid,
      }),
    ).rejects.toThrow(
      "Unable to resolve a kid for the Refresh Token JOSE header.",
    );
  });
});
