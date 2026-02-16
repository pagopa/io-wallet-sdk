import type {
  ItWalletCredentialVerifierMetadata,
  ItWalletCredentialVerifierMetadataV1_3,
} from "@pagopa/io-wallet-oid-federation";

import { CallbackContext } from "@openid4vc/oauth2";
import { Base64 } from "js-base64";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CreateAuthorizationResponseError } from "../../errors";
import { createAuthorizationResponse } from "../create-authorization-response";

const mockRpMetadata = {
  application_type: "web" as const,
  authorization_encrypted_response_alg: "RSA-OAEP-256",
  authorization_encrypted_response_enc: "A128CBC-HS256",
  authorization_signed_response_alg: "ES256",
  client_id: "https://eaa-provider.example.org",
  client_name: "Organization Name",
  contacts: ["informazioni@example.it", "protocollo@pec.example.it"],
  default_acr_values: [
    "https://trust-registry.eid-wallet.example.it/loa/substantial",
    "https://trust-registry.eid-wallet.example.it/loa/high",
  ],
  jwks: {
    keys: [
      {
        crv: "P-256",
        kid: "f10aca0992694b3581f6f699bfc8a2c6cc687725",
        kty: "EC" as "EC" | "RSA",
        x: "jE2RpcQbFQxKpMqehahgZv6smmXD0i/LTP2QRzMADk4",
        y: "qkMx5iqt5PhPu5tfctS6HsP+FmLgrxfrzUV2GwMQuh8",
      },
    ],
  },
  request_object_signing_alg_values_supported: ["ES256", "ES384", "ES512"],
  request_uris: ["https://eaa-provider.example.org/request_uri"],
  response_uris: ["https://eaa-provider.example.org/response_uri"],
  vp_formats: {
    "dc+sd-jwt": {
      "sd-jwt_alg_values": ["ES256", "ES384", "ES512"],
    },
  },
};

const MOCK_VP_TOKEN = ["vp_token1"];
const MOCK_STATE = "TEST_STATE";
const MOCK_RP_CLIENT_ID = "TEST_RP_CLIENT";
const MOCK_NONCE = "TEST_NONCE";
const REQOBJ_MOCK_NONCE = "REQ_TEST_NONCE";

const mockEncryptJwe = vi.fn((encrytor, data) => ({
  encryptionJwk: encrytor.publicJwk,
  jwe: `${data}_ENCRYPTED`,
}));

const callbacks: Pick<CallbackContext, "encryptJwe" | "generateRandom"> = {
  encryptJwe: mockEncryptJwe,
  generateRandom: () => new Uint8Array(Buffer.from(MOCK_NONCE)),
};

const ENCODED_NONCE = Base64.encode(MOCK_NONCE, true);
const REQOBJ_ENCODED_NONCE = Base64.encode(REQOBJ_MOCK_NONCE, true);

const mockRpMetadataV1_3: ItWalletCredentialVerifierMetadataV1_3 = {
  application_type: "web",
  client_id: "https://relying-party.example.org",
  client_name: "Example Relying Party V1.3",
  encrypted_response_enc_values_supported: ["A256GCM"],
  jwks: {
    keys: [
      {
        crv: "P-256",
        kid: "v13-key-1",
        kty: "EC",
        x: "jE2RpcQbFQxKpMqehahgZv6smmXD0i/LTP2QRzMADk4",
        y: "qkMx5iqt5PhPu5tfctS6HsP+FmLgrxfrzUV2GwMQuh8",
      },
    ],
  },
  logo_uri: "https://relying-party.example.org/public/logo.svg",
  request_uris: ["https://relying-party.example.org/request_uri"],
  response_uris: ["https://relying-party.example.org/response_uri"],
  vp_formats_supported: {
    "dc+sd-jwt": {
      "kb-jwt_alg_values": ["ES256"],
      "sd-jwt_alg_values": ["ES256", "ES384", "ES512"],
    },
    mso_mdoc: {
      deviceauth_alg_values: [-7, -35, -36],
      issuerauth_alg_values: [-7, -35, -36],
    },
  },
};

beforeEach(() => {
  vi.resetAllMocks();
});

describe("createAuthorizationResponseTests", () => {
  it("should create an encrypted authorization response successfully", async () => {
    const response = await createAuthorizationResponse({
      callbacks,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        response_mode: "direct_post.jwt",
        response_type: "vp_token",
        state: MOCK_STATE,
      },
      rpJwks: mockRpMetadata,
      vp_token: MOCK_VP_TOKEN,
    });

    expect(response.jarm?.responseJwe).toMatch(/_ENCRYPTED$/);
    expect(response.authorizationResponsePayload).toEqual({
      state: MOCK_STATE,
      vp_token: MOCK_VP_TOKEN,
    });

    const encryptArgs = mockEncryptJwe.mock.calls[0];
    if (!encryptArgs) {
      throw new Error();
    }
    expect(encryptArgs[0]).toMatchObject({
      apu: ENCODED_NONCE,
      apv: REQOBJ_ENCODED_NONCE,
    });
  });

  it("should throw in case there are no jwks in the client metadata", async () => {
    const rpMetadataWithoutKeys: ItWalletCredentialVerifierMetadata = {
      ...mockRpMetadata,
      jwks: {
        keys: [],
      },
    };
    await expect(
      createAuthorizationResponse({
        callbacks,
        requestObject: {
          client_id: MOCK_RP_CLIENT_ID,
          nonce: REQOBJ_MOCK_NONCE,
          response_mode: "direct_post.jwt",
          response_type: "vp_token",
          state: MOCK_STATE,
        },
        rpJwks: rpMetadataWithoutKeys,
        vp_token: MOCK_VP_TOKEN,
      }),
    ).rejects.toThrow(CreateAuthorizationResponseError);
  });
});

describe("createAuthorizationResponse v1.3 metadata support", () => {
  it("should create authorization response with v1.3 metadata and explicit JARM parameters", async () => {
    const response = await createAuthorizationResponse({
      authorization_encrypted_response_alg: "ECDH-ES",
      authorization_encrypted_response_enc: "A256GCM",
      callbacks,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        response_mode: "direct_post.jwt",
        response_type: "vp_token",
        state: MOCK_STATE,
      },
      rpJwks: mockRpMetadataV1_3,
      vp_token: MOCK_VP_TOKEN,
    });

    expect(response.jarm?.responseJwe).toMatch(/_ENCRYPTED$/);
    expect(response.authorizationResponsePayload).toMatchObject({
      state: MOCK_STATE,
      vp_token: MOCK_VP_TOKEN,
    });
  });

  it("should use default JARM algorithms for v1.3 metadata when not provided", async () => {
    const response = await createAuthorizationResponse({
      callbacks,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        response_mode: "direct_post.jwt",
        response_type: "vp_token",
        state: MOCK_STATE,
      },
      rpJwks: mockRpMetadataV1_3,
      vp_token: MOCK_VP_TOKEN,
    });

    // Should succeed with defaults: ECDH-ES, A256GCM (from encrypted_response_enc_values_supported)
    expect(response.jarm?.responseJwe).toMatch(/_ENCRYPTED$/);
    expect(response.authorizationResponsePayload).toMatchObject({
      state: MOCK_STATE,
      vp_token: MOCK_VP_TOKEN,
    });
  });

  it("should derive encryption encoding from encrypted_response_enc_values_supported for v1.3", async () => {
    const metadataWith192GCM: ItWalletCredentialVerifierMetadataV1_3 = {
      ...mockRpMetadataV1_3,
      encrypted_response_enc_values_supported: ["A192GCM", "A256GCM"],
    };

    const response = await createAuthorizationResponse({
      authorization_encrypted_response_alg: "ECDH-ES",
      // Not providing authorization_encrypted_response_enc to test fallback
      callbacks,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        response_mode: "direct_post.jwt",
        response_type: "vp_token",
        state: MOCK_STATE,
      },
      rpJwks: metadataWith192GCM,
      vp_token: MOCK_VP_TOKEN,
    });

    // Should use first value from encrypted_response_enc_values_supported (A192GCM)
    expect(response.jarm?.responseJwe).toBeDefined();
    expect(response.authorizationResponsePayload).toMatchObject({
      vp_token: MOCK_VP_TOKEN,
    });
  });

  it("should maintain backward compatibility with v1.0 metadata (without explicit JARM parameters)", async () => {
    const response = await createAuthorizationResponse({
      callbacks,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        response_mode: "direct_post.jwt",
        response_type: "vp_token",
        state: MOCK_STATE,
      },
      rpJwks: mockRpMetadata, // v1.0 metadata
      vp_token: MOCK_VP_TOKEN,
    });

    // Should work with v1.0 metadata by reading JARM config from rpJwks
    expect(response.jarm?.responseJwe).toMatch(/_ENCRYPTED$/);
    expect(response.authorizationResponsePayload).toMatchObject({
      state: MOCK_STATE,
      vp_token: MOCK_VP_TOKEN,
    });
  });
});

describe("createAuthorizationResponse client_id prefix validation", () => {
  it("should throw when x509_hash client_id is used without client_metadata", async () => {
    await expect(
      createAuthorizationResponse({
        callbacks,
        requestObject: {
          client_id: "x509_hash:https://rp.example.org",
          nonce: REQOBJ_MOCK_NONCE,
          response_mode: "direct_post.jwt",
          response_type: "vp_token",
          state: MOCK_STATE,
        },
        rpJwks: mockRpMetadata,
        vp_token: MOCK_VP_TOKEN,
      }),
    ).rejects.toThrow(CreateAuthorizationResponseError);
  });

  it("should throw when openid_federation client_id is used with client_metadata", async () => {
    await expect(
      createAuthorizationResponse({
        callbacks,
        requestObject: {
          client_id: "openid_federation:https://rp.example.org",
          client_metadata: {
            jwks: mockRpMetadata.jwks,
            vp_formats_supported: {},
          },
          nonce: REQOBJ_MOCK_NONCE,
          response_mode: "direct_post.jwt",
          response_type: "vp_token",
          state: MOCK_STATE,
        },
        rpJwks: mockRpMetadata,
        vp_token: MOCK_VP_TOKEN,
      }),
    ).rejects.toThrow(CreateAuthorizationResponseError);
  });

  it("should succeed when x509_hash client_id is used with client_metadata", async () => {
    const response = await createAuthorizationResponse({
      callbacks,
      requestObject: {
        client_id: "x509_hash:https://rp.example.org",
        client_metadata: {
          encrypted_response_enc_values_supported: ["A192GCM"],
          jwks: mockRpMetadata.jwks,
          vp_formats_supported: {},
        },
        nonce: REQOBJ_MOCK_NONCE,
        response_mode: "direct_post.jwt",
        response_type: "vp_token",
        state: MOCK_STATE,
      },
      rpJwks: mockRpMetadata,
      vp_token: MOCK_VP_TOKEN,
    });

    expect(response.jarm?.responseJwe).toBeDefined();
    const encryptArgs = mockEncryptJwe.mock.calls[0] as unknown as [
      { enc: string },
      string,
    ];
    expect(encryptArgs[0].enc).toBe("A192GCM");
  });
});
