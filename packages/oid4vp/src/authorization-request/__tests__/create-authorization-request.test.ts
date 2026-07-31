/* eslint-disable max-lines-per-function */
import { createJarRequest } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Oid4vpError } from "../../errors";
import {
  type CreateAuthorizationRequestOptionsV1_0,
  type CreateAuthorizationRequestOptionsV1_3,
  type CreateAuthorizationRequestOptionsV1_4,
  createAuthorizationRequest,
} from "../create-authorization-request";
import { Openid4vpAuthorizationRequestPayload } from "../z-authorization-request";

vi.mock("@pagopa/io-wallet-oauth2", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@pagopa/io-wallet-oauth2")>();
  return {
    ...actual,
    createJarRequest: vi.fn(),
  };
});

const configV1_0 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
});

const configV1_3 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const configV1_4 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
});

const authorizationRequestPayload: Openid4vpAuthorizationRequestPayload = {
  client_id: "client-123",
  dcql_query: {},
  iss: "client-123",
  nonce: "nonce-123",
  response_mode: "direct_post.jwt",
  response_type: "vp_token",
  response_uri: "https://wallet.example.org/response",
  state: "state-123",
};

const openidFederationAuthorizationRequestPayload = {
  ...authorizationRequestPayload,
  client_id: "openid_federation:https://rp.example.org",
  iss: "openid_federation:https://rp.example.org",
};

const legacyHttpsAuthorizationRequestPayload = {
  ...authorizationRequestPayload,
  client_id: "https://rp.example.org",
  iss: "https://rp.example.org",
};

const x509HashAuthorizationRequestPayload = {
  ...authorizationRequestPayload,
  client_id: "x509_hash:certificate-hash",
  iss: "x509_hash:certificate-hash",
};

const jar = {
  expiresInSeconds: 600,
  jwtSigner: {
    alg: "ES256",
    kid: "kid-123",
    method: "federation" as const,
    trustChain: ["entity-statement-jwt"] as [string, ...string[]],
  },
  requestUri: "https://rp.example.org/request.jwt",
};

const jarV1_3 = {
  expiresInSeconds: 600,
  jwtSigner: {
    alg: "ES256",
    kid: "kid-123",
    method: "x5c" as const,
    x5c: ["leaf-certificate"],
  },
  requestUri: "https://rp.example.org/request.jwt",
};

const callbacks = {
  signJwt: vi.fn(),
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("createAuthorizationRequest", () => {
  it("creates an authorization request URL with default openid4vp scheme", async () => {
    vi.mocked(createJarRequest).mockResolvedValue({
      authorizationRequestJwt: "signed.jwt.value",
      jarAuthorizationRequest: {
        client_id: "client-123",
        request_uri: "https://rp.example.org/request.jwt",
      },
      signerJwk: {
        crv: "P-256",
        kty: "EC",
        x: "x-value",
        y: "y-value",
      },
    });

    const result = await createAuthorizationRequest({
      authorizationRequestPayload,
      callbacks,
      config: configV1_0,
      jar: {
        ...jar,
        additionalJwtPayload: { custom: "value" },
      },
    });

    expect(createJarRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        additionalJwtPayload: {
          aud: "https://rp.example.org/request.jwt",
          custom: "value",
        },
        authorizationRequestHeader: {
          alg: "ES256",
          kid: "kid-123",
          trust_chain: ["entity-statement-jwt"],
          typ: "oauth-authz-req+jwt",
        },
      }),
    );
    expect(result.authorizationRequest).toBe(
      "openid4vp://?client_id=client-123&request_uri=https%3A%2F%2Frp.example.org%2Frequest.jwt",
    );
    expect(result.authorizationRequestObject).toEqual({
      client_id: "client-123",
      request_uri: "https://rp.example.org/request.jwt",
    });
  });

  it("narrows V1_0 signer requirements by config version at compile time", () => {
    const optionsV1_0: CreateAuthorizationRequestOptionsV1_0 = {
      authorizationRequestPayload,
      callbacks,
      config: configV1_0,
      jar,
    };

    const optionsV1_3: CreateAuthorizationRequestOptionsV1_3 = {
      authorizationRequestPayload,
      callbacks,
      config: configV1_3,
      jar: jarV1_3,
    };

    const optionsV1_4: CreateAuthorizationRequestOptionsV1_4 = {
      authorizationRequestPayload,
      callbacks,
      config: configV1_4,
      jar,
    };

    expect(optionsV1_0.jar.jwtSigner.method).toBe("federation");
    expect(optionsV1_3.jar.jwtSigner.method).toBe("x5c");
    expect(optionsV1_4.jar.jwtSigner.method).toBe("federation");

    const invalidV1_0 = {
      authorizationRequestPayload,
      callbacks,
      config: configV1_0,
      // @ts-expect-error v1.0 only accepts federation signers
      jar: jarV1_3,
    } satisfies CreateAuthorizationRequestOptionsV1_0;

    expect(invalidV1_0).toBeDefined();
  });

  it("does not overwrite additionalJwtPayload.aud when already provided", async () => {
    vi.mocked(createJarRequest).mockResolvedValue({
      authorizationRequestJwt: "signed.jwt.value",
      jarAuthorizationRequest: {
        client_id: "client-123",
        request_uri: "https://rp.example.org/request.jwt",
      },
      signerJwk: {
        crv: "P-256",
        kty: "EC",
        x: "x-value",
        y: "y-value",
      },
    });

    await createAuthorizationRequest({
      authorizationRequestPayload,
      callbacks,
      config: configV1_0,
      jar: {
        ...jar,
        additionalJwtPayload: {
          aud: "https://audience.example.org",
          custom: "value",
        },
      },
    });

    expect(createJarRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        additionalJwtPayload: {
          aud: "https://audience.example.org",
          custom: "value",
        },
      }),
    );
  });

  it("creates an authorization request URL in v1.3 with an x5c signer", async () => {
    vi.mocked(createJarRequest).mockResolvedValue({
      authorizationRequestJwt: "signed.jwt.value",
      jarAuthorizationRequest: {
        client_id: "x509_hash:certificate-hash",
        request_uri: "https://rp.example.org/request.jwt",
      },
      signerJwk: {
        crv: "P-256",
        kty: "EC",
        x: "x-value",
        y: "y-value",
      },
    });

    const result = await createAuthorizationRequest({
      authorizationRequestPayload: x509HashAuthorizationRequestPayload,
      callbacks,
      config: configV1_3,
      jar: jarV1_3,
      scheme: "https://wallet.example.org/authorize?existing=1",
    });

    expect(createJarRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        authorizationRequestHeader: {
          alg: "ES256",
          kid: "kid-123",
          typ: "oauth-authz-req+jwt",
          x5c: ["leaf-certificate"],
        },
      }),
    );
    expect(result.authorizationRequest).toBe(
      "https://wallet.example.org/authorize?existing=1&client_id=x509_hash%3Acertificate-hash&request_uri=https%3A%2F%2Frp.example.org%2Frequest.jwt",
    );
  });

  it("creates a v1.3 openid_federation authorization request with a federation signer", async () => {
    vi.mocked(createJarRequest).mockResolvedValue({
      authorizationRequestJwt: "signed.jwt.value",
      jarAuthorizationRequest: {
        client_id: "openid_federation:https://rp.example.org",
        request_uri: "https://rp.example.org/request.jwt",
      },
      signerJwk: {
        crv: "P-256",
        kty: "EC",
        x: "x-value",
        y: "y-value",
      },
    });

    await createAuthorizationRequest({
      authorizationRequestPayload: openidFederationAuthorizationRequestPayload,
      callbacks,
      config: configV1_3,
      jar,
    });

    expect(createJarRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        authorizationRequestHeader: {
          alg: "ES256",
          kid: "kid-123",
          trust_chain: ["entity-statement-jwt"],
          typ: "oauth-authz-req+jwt",
        },
      }),
    );
  });

  it("creates a v1.4 openid_federation authorization request with a federation signer", async () => {
    vi.mocked(createJarRequest).mockResolvedValue({
      authorizationRequestJwt: "signed.jwt.value",
      jarAuthorizationRequest: {
        client_id: "openid_federation:https://rp.example.org",
        request_uri: "https://rp.example.org/request.jwt",
      },
      signerJwk: {
        crv: "P-256",
        kty: "EC",
        x: "x-value",
        y: "y-value",
      },
    });

    await createAuthorizationRequest({
      authorizationRequestPayload: openidFederationAuthorizationRequestPayload,
      callbacks,
      config: configV1_4,
      jar,
    });

    expect(createJarRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        authorizationRequestHeader: {
          alg: "ES256",
          kid: "kid-123",
          trust_chain: ["entity-statement-jwt"],
          typ: "oauth-authz-req+jwt",
        },
      }),
    );
  });

  it("rejects openid_federation authorization requests with an x5c signer before JAR creation", async () => {
    await expect(
      createAuthorizationRequest({
        authorizationRequestPayload:
          openidFederationAuthorizationRequestPayload,
        callbacks,
        config: configV1_3,
        jar: jarV1_3,
      }),
    ).rejects.toThrow(Oid4vpError);

    expect(createJarRequest).not.toHaveBeenCalled();
  });

  it("rejects legacy HTTPS authorization requests with an x5c signer before JAR creation", async () => {
    await expect(
      createAuthorizationRequest({
        authorizationRequestPayload: legacyHttpsAuthorizationRequestPayload,
        callbacks,
        config: configV1_3,
        jar: jarV1_3,
      }),
    ).rejects.toThrow(Oid4vpError);

    expect(createJarRequest).not.toHaveBeenCalled();
  });

  it("rejects x509_hash authorization requests with a federation signer before JAR creation", async () => {
    await expect(
      createAuthorizationRequest({
        authorizationRequestPayload: x509HashAuthorizationRequestPayload,
        callbacks,
        config: configV1_3,
        jar,
      }),
    ).rejects.toThrow(Oid4vpError);

    expect(createJarRequest).not.toHaveBeenCalled();
  });

  it("throws Oid4vpError when authorization payload is invalid", async () => {
    await expect(
      createAuthorizationRequest({
        authorizationRequestPayload: {
          ...authorizationRequestPayload,
          nonce: undefined as unknown as string,
        },
        callbacks,
        config: configV1_0,
        jar,
      }),
    ).rejects.toThrow(Oid4vpError);

    await expect(
      createAuthorizationRequest({
        authorizationRequestPayload: {
          ...authorizationRequestPayload,
          nonce: undefined as unknown as string,
        },
        callbacks,
        config: configV1_0,
        jar,
      }),
    ).rejects.toThrow();
  });

  it("throws Oid4vpError for invalid v1.0 header", async () => {
    await expect(
      createAuthorizationRequest({
        authorizationRequestPayload,
        callbacks,
        config: configV1_0,
        jar: {
          ...jar,
          jwtSigner: {
            alg: "ES256",
            method: "federation",
          } as CreateAuthorizationRequestOptionsV1_0["jar"]["jwtSigner"],
        },
      }),
    ).rejects.toThrow(Oid4vpError);
  });
});
