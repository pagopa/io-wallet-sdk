import { createJarRequest } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { Oid4vpError } from "../../errors";
import { createAuthorizationRequest } from "../create-authorization-request";
import { AuthorizationRequestObject } from "../z-request-object";

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

const authorizationRequestPayload: AuthorizationRequestObject = {
  client_id: "client-123",
  dcql_query: {},
  iss: "client-123",
  nonce: "nonce-123",
  response_mode: "direct_post.jwt",
  response_type: "vp_token",
  response_uri: "https://wallet.example.org/response",
  state: "state-123",
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

  it("throws Oid4vpError in v1.3 when x5c is missing", async () => {
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

    await expect(
      createAuthorizationRequest({
        authorizationRequestPayload,
        callbacks,
        config: configV1_3,
        jar,
        scheme: "https://wallet.example.org/authorize?existing=1",
      }),
    ).rejects.toThrow(Oid4vpError);
  });

  it("throws Oid4vpError when authorization payload is invalid", async () => {
    await expect(
      createAuthorizationRequest({
        authorizationRequestPayload: {
          ...authorizationRequestPayload,
          state: undefined as unknown as string,
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
          state: undefined as unknown as string,
        },
        callbacks,
        config: configV1_0,
        jar,
      }),
    ).rejects.toThrow(
      "Invalid authorization request. Could not parse openid4vp authorization request.",
    );
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
            didUrl: "did:key:z6MkiTBz1xAA9nVwJ7LFw7kS2F8Q6XvX1YfC5gPA1JxH7M5M",
            method: "did",
          },
        },
      }),
    ).rejects.toThrow(Oid4vpError);
  });
});
