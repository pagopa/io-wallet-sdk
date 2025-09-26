import { beforeEach, describe, expect, it, vi } from "vitest";

import { PkceCodeChallengeMethod, createPkce } from "../../pkce";
import {
  CreatePushedAuthorizationRequestOptions,
  createPushedAuthorizationRequest,
} from "../create-authorization-request";

vi.mock("../../pkce");
vi.mock("@openid4vc/utils", () => ({
  encodeToBase64Url: vi.fn((data) => `base64url_${data}`),
}));

const mockCreatePkce = vi.mocked(createPkce);

describe("createPushedAuthorizationRequest", () => {
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
      x: "test-x",
      y: "test-y",
    },
  };

  const baseOptions: CreatePushedAuthorizationRequestOptions = {
    audience: "https://issuer.example.com",
    authorization_details: [
      {
        credential_configuration_id: "test-config",
        type: "openid_credential",
      },
    ],
    callbacks: mockCallbacks,
    clientId: "test-client-id",
    codeChallengeMethodsSupported: ["S256"],
    dpop: {
      signer: mockSigner,
    },
    redirectUri: "https://client.example.com/callback",
    responseMode: "form_post",
    scope: "openid",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockCallbacks.generateRandom.mockResolvedValue(
      new Uint8Array([1, 2, 3, 4]),
    );
    mockCallbacks.signJwt.mockResolvedValue({ jwt: "test-jwt-token" });
    mockCreatePkce.mockResolvedValue({
      codeChallenge: "test-code-challenge",
      codeChallengeMethod: PkceCodeChallengeMethod.S256,
      codeVerifier: "test-code-verifier",
    });
  });

  it("should create a pushed authorization request with PKCE", async () => {
    const result = await createPushedAuthorizationRequest(baseOptions);

    expect(mockCreatePkce).toHaveBeenCalledWith({
      allowedCodeChallengeMethods: ["S256"],
      callbacks: mockCallbacks,
      codeVerifier: undefined,
    });

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: {
        alg: "ES256",
        kid: "test-kid",
        typ: "jwt",
      },
      payload: expect.objectContaining({
        aud: "https://issuer.example.com",
        authorization_details: [
          {
            credential_configuration_id: "test-config",
            type: "openid_credential",
          },
        ],
        client_id: "test-client-id",
        code_challenge: "test-code-challenge",
        code_challenge_method: "S256",
        exp: expect.any(Number),
        iat: expect.any(Number),
        iss: "test-kid",
        jti: "base64url_1,2,3,4",
        redirect_uri: "https://client.example.com/callback",
        response_mode: "form_post",
        response_type: "code",
        scope: "openid",
        state: "base64url_1,2,3,4",
      }),
    });

    expect(result).toEqual({
      client_id: "test-client-id",
      request: "test-jwt-token",
    });
  });

  it("should use provided PKCE code verifier", async () => {
    const optionsWithCodeVerifier = {
      ...baseOptions,
      pkceCodeVerifier: "custom-code-verifier",
    };

    await createPushedAuthorizationRequest(optionsWithCodeVerifier);

    expect(mockCreatePkce).toHaveBeenCalledWith({
      allowedCodeChallengeMethods: ["S256"],
      callbacks: mockCallbacks,
      codeVerifier: "custom-code-verifier",
    });
  });

  it("should set correct JWT payload timestamps", async () => {
    const mockNow = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(mockNow);

    await createPushedAuthorizationRequest(baseOptions);

    const expectedIat = Math.floor(mockNow);
    const expectedExp = expectedIat + 3600;

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        exp: expectedExp,
        iat: expectedIat,
      }),
    });
  });

  it("should use signer kid as issuer in JWT payload", async () => {
    const customSigner = {
      alg: "ES256",
      method: "jwk" as const,
      publicJwk: {
        crv: "P-256",
        kid: "custom-signer-kid",
        kty: "EC",
        x: "custom-x",
        y: "custom-y",
      },
    };

    const optionsWithCustomSigner = {
      ...baseOptions,
      dpop: {
        signer: customSigner,
      },
    };

    await createPushedAuthorizationRequest(optionsWithCustomSigner);

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(customSigner, {
      header: expect.objectContaining({
        kid: "custom-signer-kid",
      }),
      payload: expect.objectContaining({
        iss: "custom-signer-kid",
      }),
    });
  });

  it("should use provided state and jti parameters when passed in options", async () => {
    const customState = "custom-state-value";
    const customJti = "custom-jti-value";

    const optionsWithStateAndJti = {
      ...baseOptions,
      jti: customJti,
      state: customState,
    };

    await createPushedAuthorizationRequest(optionsWithStateAndJti);

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        jti: customJti,
        state: customState,
      }),
    });
  });
});
