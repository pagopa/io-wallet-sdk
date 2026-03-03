import { beforeEach, describe, expect, it, vi } from "vitest";

import { Jwk } from "../../common/jwk/z-jwk";
import { Oauth2Error } from "../../errors";
import {
  CreateJarRequestOptions,
  createJarRequest,
} from "../create-jar-request";

const signerJwk: Jwk = {
  crv: "P-256",
  kty: "EC",
  x: "signer-x",
  y: "signer-y",
};

const encryptionJwk: Jwk = {
  crv: "P-256",
  kty: "EC",
  x: "enc-x",
  y: "enc-y",
};

const jwtSigner = {
  alg: "ES256",
  method: "jwk" as const,
  publicJwk: signerJwk,
};

const jweEncryptor = {
  alg: "ECDH-ES",
  enc: "A256GCM",
  method: "jwk" as const,
  publicJwk: encryptionJwk,
};

const callbacks: CreateJarRequestOptions["callbacks"] = {
  encryptJwe: vi.fn(),
  signJwt: vi.fn(),
};

const now = new Date("2025-01-01T00:00:00.000Z");

const baseOptions: CreateJarRequestOptions = {
  authorizationRequestHeader: {
    alg: "ES256",
    jwk: signerJwk,
    typ: "oauth-authz-req+jwt",
  },
  authorizationRequestPayload: {
    client_id: "wallet-client-id",
    nonce: "test-nonce",
    response_type: "code",
    scope: "openid",
  },
  callbacks,
  expiresInSeconds: 300,
  jwtSigner,
  now,
};

describe("createJarAuthorizationRequest", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(callbacks.signJwt).mockResolvedValue({
      jwt: "signed-jar-jwt",
      signerJwk,
    });
    if (!callbacks.encryptJwe) {
      throw new Error("encryptJwe callback is not defined");
    }
    vi.mocked(callbacks.encryptJwe).mockResolvedValue({
      encryptionJwk,
      jwe: "encrypted-jar-jwe",
    });
  });

  it("creates a by-value JAR request with a signed request object", async () => {
    const result = await createJarRequest(baseOptions);

    expect(callbacks.signJwt).toHaveBeenCalledWith(jwtSigner, {
      header: {
        alg: "ES256",
        jwk: signerJwk,
        typ: "oauth-authz-req+jwt",
      },
      payload: expect.objectContaining({
        client_id: "wallet-client-id",
        exp: 1735689900,
        iat: 1735689600,
        nonce: "test-nonce",
        response_type: "code",
        scope: "openid",
      }),
    });
    expect(callbacks.encryptJwe).not.toHaveBeenCalled();

    expect(result).toEqual({
      authorizationRequestJwt: "signed-jar-jwt",
      encryptionJwk: undefined,
      jarAuthorizationRequest: {
        client_id: "wallet-client-id",
        request: "signed-jar-jwt",
      },
      signerJwk,
    });
  });

  it("creates a by-reference JAR request when requestUri is provided", async () => {
    const result = await createJarRequest({
      ...baseOptions,
      requestUri: "https://wallet.example.org/request.jwt",
    });

    expect(result.jarAuthorizationRequest).toEqual({
      client_id: "wallet-client-id",
      request_uri: "https://wallet.example.org/request.jwt",
    });
  });

  it("encrypts the signed request object when jweEncryptor is provided", async () => {
    const result = await createJarRequest({
      ...baseOptions,
      jweEncryptor,
    });

    expect(callbacks.encryptJwe).toHaveBeenCalledWith(
      jweEncryptor,
      "signed-jar-jwt",
    );
    expect(result).toEqual({
      authorizationRequestJwt: "encrypted-jar-jwe",
      encryptionJwk,
      jarAuthorizationRequest: {
        client_id: "wallet-client-id",
        request: "encrypted-jar-jwe",
      },
      signerJwk,
    });
  });

  it("throws when jweEncryptor is provided and encryptJwe callback is missing", async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { encryptJwe, ...callbacksWithoutEncryptJwe } = callbacks;

    await expect(
      createJarRequest({
        ...baseOptions,
        callbacks: callbacksWithoutEncryptJwe,
        jweEncryptor,
      }),
    ).rejects.toThrow(
      new Oauth2Error(
        "callbacks.encryptJwe is required when jweEncryptor is provided",
      ),
    );
  });
});
