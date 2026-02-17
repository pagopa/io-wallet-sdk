import { beforeEach, describe, expect, it, vi } from "vitest";

import { PkceCodeChallengeMethod, createPkce } from "../../pkce";
import {
  CreatePushedAuthorizationRequestOptions,
  createPushedAuthorizationRequest,
} from "../create-authorization-request";

vi.mock("../../pkce");
vi.mock(import("@openid4vc/utils"), async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    encodeToBase64Url: vi.fn((data) => `base64url_${data}`),
  };
});

const mockCreatePkce = vi.mocked(createPkce);

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

const mockCallbacks = {
  generateRandom: vi.fn(),
  hash: vi.fn(),
  signJwt: vi.fn(),
};

const baseOptions: CreatePushedAuthorizationRequestOptions = {
  audience: "https://issuer.example.com",
  authorization_details: [
    {
      credential_configuration_id: "test-config",
      type: "openid_credential",
    },
  ],
  authorizationServerMetadata: {
    require_signed_request_object: true,
  },
  callbacks: mockCallbacks,
  clientId: "test-client-id",
  codeChallengeMethodsSupported: ["S256"],
  dpop: {
    signer: mockSigner,
  },
  redirectUri: "https://client.example.com/callback",
  responseMode: "form_post",
};

const setupMocks = () => {
  vi.restoreAllMocks();
  mockCallbacks.generateRandom.mockResolvedValue(new Uint8Array([1, 2, 3, 4]));
  mockCallbacks.signJwt.mockResolvedValue({ jwt: "test-jwt-token" });
  mockCreatePkce.mockResolvedValue({
    codeChallenge: "test-code-challenge",
    codeChallengeMethod: PkceCodeChallengeMethod.S256,
    codeVerifier: "test-code-verifier",
  });
};

describe("createPushedAuthorizationRequest", () => {
  beforeEach(setupMocks);

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
        state: "base64url_1,2,3,4",
      }),
    });

    expect(result).toEqual({
      client_id: "test-client-id",
      pkceCodeVerifier: "test-code-verifier",
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

  it("should throw error with no authorization_details and no scope", async () => {
    const optionsWithoutScope = {
      ...baseOptions,
      authorization_details: undefined,
      scope: undefined,
    };

    await expect(
      createPushedAuthorizationRequest(optionsWithoutScope),
    ).rejects.toThrow(Error);
  });

  it("should create request with only scope (no authorization_details)", async () => {
    const optionsWithoutAuthDetails = {
      ...baseOptions,
      authorization_details: undefined,
      scope: "openid profile",
    };

    const result = await createPushedAuthorizationRequest(
      optionsWithoutAuthDetails,
    );

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        authorization_details: undefined,
        scope: "openid profile",
      }),
    });

    expect(result).toEqual({
      client_id: "test-client-id",
      pkceCodeVerifier: "test-code-verifier",
      request: "test-jwt-token",
    });
  });
});

describe("createPushedAuthorizationRequest - timestamp handling", () => {
  beforeEach(setupMocks);

  it("should set correct JWT payload timestamps", async () => {
    const mockNow = Date.now();
    vi.spyOn(Date, "now").mockReturnValue(mockNow);

    await createPushedAuthorizationRequest(baseOptions);

    const expectedIat = Math.floor(mockNow / 1000);
    const expectedExp = expectedIat + 3600;

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        exp: expectedExp,
        iat: expectedIat,
      }),
    });
  });

  it("should use provided issuedAt and expiresAt in JWT payload", async () => {
    const issuedAt = new Date("2025-01-01T00:00:00.000Z");
    const expiresAt = new Date("2025-01-01T00:05:00.000Z");

    await createPushedAuthorizationRequest({
      ...baseOptions,
      expiresAt,
      issuedAt,
    });

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        exp: Math.floor(expiresAt.getTime() / 1000),
        iat: Math.floor(issuedAt.getTime() / 1000),
      }),
    });
  });

  it("should default expiresAt to issuedAt plus one hour when only issuedAt is provided", async () => {
    const issuedAt = new Date("2025-01-01T00:00:00.000Z");

    await createPushedAuthorizationRequest({
      ...baseOptions,
      issuedAt,
    });

    const expectedIat = Math.floor(issuedAt.getTime() / 1000);
    const expectedExp = expectedIat + 3600;

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        exp: expectedExp,
        iat: expectedIat,
      }),
    });
  });

  it("should default issuedAt to current time when only expiresAt is provided", async () => {
    const mockDate = new Date("2025-01-01T01:00:00.000Z");
    vi.useFakeTimers();
    vi.setSystemTime(mockDate);

    const expiresAt = new Date("2025-01-01T02:00:00.000Z");

    await createPushedAuthorizationRequest({
      ...baseOptions,
      expiresAt,
    });

    const expectedIat = Math.floor(mockDate.getTime() / 1000);
    const expectedExp = Math.floor(expiresAt.getTime() / 1000);

    expect(mockCallbacks.signJwt).toHaveBeenCalledWith(mockSigner, {
      header: expect.any(Object),
      payload: expect.objectContaining({
        exp: expectedExp,
        iat: expectedIat,
      }),
    });

    vi.useRealTimers();
  });
});

describe("createPushedAuthorizationRequest - JAR signing policy", () => {
  beforeEach(setupMocks);

  it("should create unsigned PAR when require_signed_request_object is false", async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { dpop: _, ...baseWithoutDpop } = baseOptions;
    const options = {
      ...baseWithoutDpop,
      authorizationServerMetadata: {
        require_signed_request_object: false,
      },
    };

    const result = await createPushedAuthorizationRequest(options);

    expect(mockCallbacks.signJwt).not.toHaveBeenCalled();
    expect(result).toEqual({
      authorizationRequest: expect.objectContaining({
        authorization_details: [
          {
            credential_configuration_id: "test-config",
            type: "openid_credential",
          },
        ],
        client_id: "test-client-id",
        code_challenge: "test-code-challenge",
        code_challenge_method: "S256",
        redirect_uri: "https://client.example.com/callback",
        response_mode: "form_post",
        response_type: "code",
        state: "base64url_1,2,3,4",
      }),
      client_id: "test-client-id",
      pkceCodeVerifier: "test-code-verifier",
    });
  });

  it("should default to unsigned PAR when authorizationServerMetadata is not provided", async () => {
    /* eslint-disable @typescript-eslint/no-unused-vars */
    const {
      authorizationServerMetadata: _,
      dpop: __,
      ...optionsWithoutMetadata
    } = baseOptions;
    /* eslint-enable @typescript-eslint/no-unused-vars */

    const result = await createPushedAuthorizationRequest(
      optionsWithoutMetadata,
    );

    expect(mockCallbacks.signJwt).not.toHaveBeenCalled();
    expect(result).toEqual({
      authorizationRequest: expect.objectContaining({
        client_id: "test-client-id",
        response_type: "code",
      }),
      client_id: "test-client-id",
      pkceCodeVerifier: "test-code-verifier",
    });
  });
});
