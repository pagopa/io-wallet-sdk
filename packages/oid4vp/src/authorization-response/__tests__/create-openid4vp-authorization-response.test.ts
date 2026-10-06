import { Oauth2Error } from "@pagopa/io-wallet-oauth2";
import {
  type Jwk,
  UnexpectedStatusCodeError,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { Openid4vpAuthorizationRequestPayload } from "../../authorization-request/z-authorization-request";

import {
  type CreateOpenid4vpAuthorizationResponseOptions,
  type JarmClientMetadata,
  createOpenid4vpAuthorizationResponse,
} from "../create-openid4vp-authorization-response";

const SIGNING_JWK: Jwk = {
  crv: "P-256",
  kid: "sig-key",
  kty: "EC",
  use: "sig",
  x: "sig-x",
  y: "sig-y",
};

const REQUEST_ENC_JWK: Jwk = {
  alg: "ECDH-ES",
  crv: "P-256",
  kid: "request-enc-key",
  kty: "EC",
  use: "enc",
  x: "req-x",
  y: "req-y",
};

const VERIFIED_ENC_JWK: Jwk = {
  alg: "ECDH-ES",
  crv: "P-256",
  kid: "trust-chain-enc-key",
  kty: "EC",
  use: "enc",
  x: "tc-x",
  y: "tc-y",
};

const REQUEST_CLIENT_METADATA: JarmClientMetadata = {
  encrypted_response_enc_values_supported: ["A256GCM"],
  jwks: { keys: [SIGNING_JWK, REQUEST_ENC_JWK] },
};

const VERIFIED_CLIENT_METADATA: JarmClientMetadata = {
  encrypted_response_enc_values_supported: ["A256GCM"],
  jwks: { keys: [VERIFIED_ENC_JWK] },
};

const SERVER_METADATA = {
  authorization_encryption_alg_values_supported: ["ECDH-ES"],
  authorization_encryption_enc_values_supported: ["A128GCM", "A256GCM"],
};

const createRequest = (
  clientId: string,
  clientMetadata: JarmClientMetadata | undefined = REQUEST_CLIENT_METADATA,
) =>
  ({
    client_id: clientId,
    client_metadata: clientMetadata,
    dcql_query: { credentials: [] },
    nonce: "request-nonce",
    response_mode: "direct_post.jwt",
    response_type: "vp_token",
    response_uri: "https://rp.example.it/response",
    state: "request-state",
  }) as unknown as Openid4vpAuthorizationRequestPayload;

const encryptJwe = vi.fn<
  (
    encryptor: { publicJwk: Jwk },
    data: string,
  ) => Promise<{ encryptionJwk: Jwk; jwe: string }>
>(async (encryptor) => ({
  encryptionJwk: encryptor.publicJwk,
  jwe: "header.key.iv.ciphertext.tag",
}));

const signJwt = vi.fn(async () => ({
  jwt: "signed.jarm.jwt",
  signerJwk: SIGNING_JWK,
}));

const createOptions = (
  overrides: Partial<CreateOpenid4vpAuthorizationResponseOptions> = {},
): CreateOpenid4vpAuthorizationResponseOptions => ({
  authorizationRequestPayload: createRequest("x509_hash:certificate-hash"),
  authorizationResponsePayload: { vp_token: { pid: ["vp-token"] } },
  callbacks: { encryptJwe, signJwt },
  jarm: {
    encryption: { nonce: "wallet-nonce" },
    serverMetadata: SERVER_METADATA,
  },
  ...overrides,
});

describe("createOpenid4vpAuthorizationResponse - client identification and encryption key", () => {
  afterEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it("throws when the response mode requires JARM but no jarm options are given", async () => {
    await expect(
      createOpenid4vpAuthorizationResponse(createOptions({ jarm: undefined })),
    ).rejects.toThrow(
      "Missing jarm options for creating Jarm response with response mode 'direct_post.jwt'",
    );
  });

  it.each([
    ["openid_federation prefix", "openid_federation:https://rp.example.it"],
    ["legacy https client_id", "https://rp.example.it"],
  ])(
    "requires externally verified clientMetadata for a %s",
    async (_, clientId) => {
      await expect(
        createOpenid4vpAuthorizationResponse(
          createOptions({
            authorizationRequestPayload: createRequest(clientId),
          }),
        ),
      ).rejects.toThrow(Oauth2Error);
      expect(encryptJwe).not.toHaveBeenCalled();
    },
  );

  it("encrypts federation responses with the provided clientMetadata, ignoring the request client_metadata", async () => {
    const result = await createOpenid4vpAuthorizationResponse(
      createOptions({
        authorizationRequestPayload: createRequest("https://rp.example.it"),
        clientMetadata: VERIFIED_CLIENT_METADATA,
      }),
    );

    expect(encryptJwe).toHaveBeenCalledWith(
      expect.objectContaining({ publicJwk: VERIFIED_ENC_JWK }),
      expect.any(String),
    );
    expect(result.jarm?.encryptionJwk).toEqual(VERIFIED_ENC_JWK);
  });

  it("encrypts x509_hash responses with the encryption key from the request client_metadata", async () => {
    const result = await createOpenid4vpAuthorizationResponse(createOptions());

    expect(encryptJwe).toHaveBeenCalledWith(
      {
        alg: "ECDH-ES",
        apu: encodeToBase64Url("wallet-nonce"),
        apv: encodeToBase64Url("request-nonce"),
        enc: "A256GCM",
        method: "jwk",
        publicJwk: REQUEST_ENC_JWK,
      },
      expect.any(String),
    );
    expect(JSON.parse(encryptJwe.mock.calls[0]?.[1] ?? "")).toEqual({
      state: "request-state",
      vp_token: { pid: ["vp-token"] },
    });
    expect(signJwt).not.toHaveBeenCalled();
    expect(result).toEqual({
      authorizationResponsePayload: {
        state: "request-state",
        vp_token: { pid: ["vp-token"] },
      },
      jarm: {
        encryptionJwk: REQUEST_ENC_JWK,
        responseJwt: "header.key.iv.ciphertext.tag",
      },
    });
  });

  it("prefers the encryption JWK given in the jarm options", async () => {
    await createOpenid4vpAuthorizationResponse(
      createOptions({
        jarm: {
          encryption: { jwk: VERIFIED_ENC_JWK, nonce: "wallet-nonce" },
          serverMetadata: SERVER_METADATA,
        },
      }),
    );

    expect(encryptJwe).toHaveBeenCalledWith(
      expect.objectContaining({ publicJwk: VERIFIED_ENC_JWK }),
      expect.any(String),
    );
  });
});

describe("createOpenid4vpAuthorizationResponse - client JWKS resolution", () => {
  afterEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it("resolves the client JWKS from jwks_uri with the fetch callback", async () => {
    const fetch = vi.fn(
      async () =>
        new Response(JSON.stringify({ keys: [REQUEST_ENC_JWK] }), {
          headers: { "content-type": "application/jwk-set+json" },
          status: 200,
        }),
    );

    await createOpenid4vpAuthorizationResponse(
      createOptions({
        authorizationRequestPayload: createRequest(
          "x509_hash:certificate-hash",
          {
            encrypted_response_enc_values_supported: ["A256GCM"],
            jwks_uri: "https://rp.example.it/jwks",
          },
        ),
        callbacks: { encryptJwe, fetch, signJwt },
      }),
    );

    expect(fetch).toHaveBeenCalledWith("https://rp.example.it/jwks", {
      headers: { Accept: "application/jwk-set+json, application/json;q=0.9" },
    });
    expect(encryptJwe).toHaveBeenCalledWith(
      expect.objectContaining({ publicJwk: REQUEST_ENC_JWK }),
      expect.any(String),
    );
  });

  it("throws UnexpectedStatusCodeError when the jwks_uri response is not 200", async () => {
    const fetch = vi.fn(
      async () =>
        new Response("Not Found", {
          headers: { "content-type": "text/plain" },
          status: 404,
        }),
    );

    await expect(
      createOpenid4vpAuthorizationResponse(
        createOptions({
          authorizationRequestPayload: createRequest(
            "x509_hash:certificate-hash",
            { jwks_uri: "https://rp.example.it/jwks" },
          ),
          callbacks: { encryptJwe, fetch, signJwt },
        }),
      ),
    ).rejects.toThrow(UnexpectedStatusCodeError);
  });

  it("throws when jwks_uri must be resolved but no fetch callback is given", async () => {
    await expect(
      createOpenid4vpAuthorizationResponse(
        createOptions({
          authorizationRequestPayload: createRequest(
            "x509_hash:certificate-hash",
            { jwks_uri: "https://rp.example.it/jwks" },
          ),
        }),
      ),
    ).rejects.toThrow("Missing fetch callback");
  });

  it("throws when the client metadata has neither jwks nor jwks_uri", async () => {
    await expect(
      createOpenid4vpAuthorizationResponse(
        createOptions({
          authorizationRequestPayload: createRequest(
            "x509_hash:certificate-hash",
            { encrypted_response_enc_values_supported: ["A256GCM"] },
          ),
        }),
      ),
    ).rejects.toThrow("Missing 'jwks' or 'jwks_uri' in client metadata");
  });

  it("throws when the enc value is not supported by the wallet", async () => {
    await expect(
      createOpenid4vpAuthorizationResponse(
        createOptions({
          authorizationRequestPayload: createRequest(
            "x509_hash:certificate-hash",
            {
              encrypted_response_enc_values_supported: ["A128CBC-HS256"],
              jwks: { keys: [REQUEST_ENC_JWK] },
            },
          ),
        }),
      ),
    ).rejects.toThrow("Invalid 'enc' value A128CBC-HS256");
  });

  it.each([
    ["authorization_encrypted_response_alg", "RSA-OAEP-256"],
    ["authorization_encrypted_response_enc", "A128CBC-HS256"],
    ["authorization_signed_response_alg", "PS256"],
  ])(
    "throws when the client declares an unsupported %s",
    async (field, value) => {
      await expect(
        createOpenid4vpAuthorizationResponse(
          createOptions({
            authorizationRequestPayload: createRequest(
              "x509_hash:certificate-hash",
              { ...REQUEST_CLIENT_METADATA, [field]: value },
            ),
            jarm: {
              encryption: { nonce: "wallet-nonce" },
              serverMetadata: {
                ...SERVER_METADATA,
                authorization_signed_response_alg_values_supported: ["ES256"],
              },
            },
          }),
        ),
      ).rejects.toThrow(`Invalid ${field} ${value}`);
      expect(encryptJwe).not.toHaveBeenCalled();
    },
  );
});

describe("createOpenid4vpAuthorizationResponse - signed responses", () => {
  afterEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it("throws when the signer alg differs from authorization_signed_response_alg", async () => {
    await expect(
      createOpenid4vpAuthorizationResponse(
        createOptions({
          authorizationRequestPayload: createRequest(
            "x509_hash:certificate-hash",
            {
              ...REQUEST_CLIENT_METADATA,
              authorization_signed_response_alg: "ES384",
            },
          ),
          jarm: {
            audience: "x509_hash:certificate-hash",
            authorizationServer: "https://wallet.example.it",
            encryption: { nonce: "wallet-nonce" },
            jwtSigner: { alg: "ES256", method: "jwk", publicJwk: SIGNING_JWK },
            serverMetadata: SERVER_METADATA,
          },
        }),
      ),
    ).rejects.toThrow("Invalid signed response alg value ES256");
  });

  it("requires audience and issuer when signing the response", async () => {
    await expect(
      createOpenid4vpAuthorizationResponse(
        createOptions({
          jarm: {
            encryption: { nonce: "wallet-nonce" },
            jwtSigner: { alg: "ES256", method: "jwk", publicJwk: SIGNING_JWK },
            serverMetadata: SERVER_METADATA,
          },
        }),
      ),
    ).rejects.toThrow("Missing required aud");

    await expect(
      createOpenid4vpAuthorizationResponse(
        createOptions({
          jarm: {
            audience: "x509_hash:certificate-hash",
            encryption: { nonce: "wallet-nonce" },
            jwtSigner: { alg: "ES256", method: "jwk", publicJwk: SIGNING_JWK },
            serverMetadata: SERVER_METADATA,
          },
        }),
      ),
    ).rejects.toThrow("Missing required iss");
  });

  it("signs then encrypts, setting exp relative to the current time", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const nowInSeconds = Math.floor(Date.now() / 1000);

    const result = await createOpenid4vpAuthorizationResponse(
      createOptions({
        jarm: {
          audience: "x509_hash:certificate-hash",
          authorizationServer: "https://wallet.example.it",
          encryption: { nonce: "wallet-nonce" },
          expiresInSeconds: 120,
          jwtSigner: { alg: "ES256", method: "jwk", publicJwk: SIGNING_JWK },
          serverMetadata: SERVER_METADATA,
        },
      }),
    );

    const expectedPayload = {
      aud: "x509_hash:certificate-hash",
      exp: nowInSeconds + 120,
      iss: "https://wallet.example.it",
      state: "request-state",
      vp_token: { pid: ["vp-token"] },
    };

    expect(signJwt).toHaveBeenCalledWith(
      { alg: "ES256", method: "jwk", publicJwk: SIGNING_JWK },
      {
        header: { alg: "ES256", jwk: SIGNING_JWK },
        payload: expectedPayload,
      },
    );
    expect(encryptJwe).toHaveBeenCalledWith(
      expect.objectContaining({ publicJwk: REQUEST_ENC_JWK }),
      "signed.jarm.jwt",
    );
    expect(result.authorizationResponsePayload).toEqual(expectedPayload);
  });
});
