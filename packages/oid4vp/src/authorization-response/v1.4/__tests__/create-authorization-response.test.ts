import type { CallbackContext } from "@pagopa/io-wallet-oauth2";
import type { ItWalletCredentialVerifierMetadataV1_3 } from "@pagopa/io-wallet-oid-federation";

import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { CreateAuthorizationResponseError } from "../../../errors";
import { createAuthorizationResponse } from "../../create-authorization-response";

const MOCK_VP_TOKEN = { pid: ["vp_token1"] as [string] };
const MOCK_STATE = "TEST_STATE";
const MOCK_RP_CLIENT_ID = "TEST_RP_CLIENT";
const MOCK_NONCE = "TEST_NONCE";
const REQOBJ_MOCK_NONCE = "REQ_TEST_NONCE";

const mockEncryptJwe = vi.fn((encryptor, data) => ({
  encryptionJwk: encryptor.publicJwk,
  jwe: `${data}_ENCRYPTED`,
}));

const callbacks: Pick<CallbackContext, "encryptJwe" | "generateRandom"> = {
  encryptJwe: mockEncryptJwe,
  generateRandom: () => new Uint8Array(Buffer.from(MOCK_NONCE)),
};

const config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_4,
});

const mockRpJwks = {
  jwks: {
    keys: [
      {
        crv: "P-256",
        kid: "rp-key-1",
        kty: "EC" as "EC" | "RSA",
        x: "jE2RpcQbFQxKpMqehahgZv6smmXD0i/LTP2QRzMADk4",
        y: "qkMx5iqt5PhPu5tfctS6HsP+FmLgrxfrzUV2GwMQuh8",
      },
    ],
  },
};

const mockClientMetadata: ItWalletCredentialVerifierMetadataV1_3 = {
  application_type: "web",
  client_id: "https://relying-party.example.org",
  client_name: "Example Relying Party",
  encrypted_response_enc_values_supported: ["A256GCM"],
  jwks: {
    keys: [
      {
        crv: "P-256",
        kid: "client-meta-key-1",
        kty: "EC",
        x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        y: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      },
    ],
  },
  logo_uri: "https://relying-party.example.org/logo.svg",
  request_uris: ["https://relying-party.example.org/request_uri"],
  response_uris: ["https://relying-party.example.org/response_uri"],
  vp_formats_supported: {
    "dc+sd-jwt": {
      "kb-jwt_alg_values": ["ES256"],
      "sd-jwt_alg_values": ["ES256"],
    },
    mso_mdoc: {
      deviceauth_alg_values: [-7],
      issuerauth_alg_values: [-7],
    },
  },
};

beforeEach(() => {
  vi.resetAllMocks();
});

describe("createAuthorizationResponse v1.4", () => {
  it("should use client_metadata.jwks when openid_federation prefix is used", async () => {
    const response = await createAuthorizationResponse({
      callbacks,
      config,
      requestObject: {
        client_id: "openid_federation:https://rp.example.org",
        client_metadata: mockClientMetadata,
        nonce: REQOBJ_MOCK_NONCE,
        state: MOCK_STATE,
      },
      rpJwks: mockRpJwks,
      vp_token: MOCK_VP_TOKEN,
    });

    expect(response.jarm.responseJwe).toBeDefined();

    const encryptArgs = mockEncryptJwe.mock.calls[0] as unknown as [
      { publicJwk: { kid: string } },
      string,
    ];
    // v1.4: client_metadata.jwks must be used even with openid_federation prefix
    expect(encryptArgs[0].publicJwk.kid).toBe(
      mockClientMetadata.jwks.keys[0]?.kid,
    );
  });

  it("should use client_metadata.encrypted_response_enc_values_supported when openid_federation prefix is used", async () => {
    const rpJwksWithEnc = {
      ...mockRpJwks,
      encrypted_response_enc_values_supported: ["A128GCM"],
    };

    await createAuthorizationResponse({
      callbacks,
      config,
      requestObject: {
        client_id: "openid_federation:https://rp.example.org",
        client_metadata: mockClientMetadata, // encrypted_response_enc_values_supported: ["A256GCM"]
        nonce: REQOBJ_MOCK_NONCE,
        state: MOCK_STATE,
      },
      rpJwks: rpJwksWithEnc,
      vp_token: MOCK_VP_TOKEN,
    });

    const encryptArgs = mockEncryptJwe.mock.calls[0] as unknown as [
      { enc: string },
      string,
    ];
    // v1.4 (RPR-113 exception): client_metadata.encrypted_response_enc_values_supported
    // takes precedence over rpJwks even with openid_federation prefix
    expect(encryptArgs[0].enc).toBe("A256GCM");
  });

  it("should fall back to rpJwks.encrypted_response_enc_values_supported when client_metadata is absent", async () => {
    const rpJwksWithEnc = {
      ...mockRpJwks,
      encrypted_response_enc_values_supported: ["A128GCM"],
    };

    await createAuthorizationResponse({
      callbacks,
      config,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        state: MOCK_STATE,
      },
      rpJwks: rpJwksWithEnc,
      vp_token: MOCK_VP_TOKEN,
    });

    const encryptArgs = mockEncryptJwe.mock.calls[0] as unknown as [
      { enc: string },
      string,
    ];
    expect(encryptArgs[0].enc).toBe("A128GCM");
  });

  it("should fall back to rpJwks when client_metadata is absent", async () => {
    const response = await createAuthorizationResponse({
      callbacks,
      config,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        state: MOCK_STATE,
      },
      rpJwks: mockRpJwks,
      vp_token: MOCK_VP_TOKEN,
    });

    expect(response.jarm.responseJwe).toBeDefined();

    const encryptArgs = mockEncryptJwe.mock.calls[0] as unknown as [
      { publicJwk: { kid: string } },
      string,
    ];
    expect(encryptArgs[0].publicJwk.kid).toBe(mockRpJwks.jwks.keys[0]?.kid);
  });

  it("should throw when x509_hash client_id is used without client_metadata", async () => {
    await expect(
      createAuthorizationResponse({
        callbacks,
        config,
        requestObject: {
          client_id: "x509_hash:https://rp.example.org",
          nonce: REQOBJ_MOCK_NONCE,
          state: MOCK_STATE,
        },
        rpJwks: mockRpJwks,
        vp_token: MOCK_VP_TOKEN,
      }),
    ).rejects.toThrow(CreateAuthorizationResponseError);
  });

  it("should include state and vp_token in the authorization response payload", async () => {
    const response = await createAuthorizationResponse({
      callbacks,
      config,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        state: MOCK_STATE,
      },
      rpJwks: mockRpJwks,
      vp_token: MOCK_VP_TOKEN,
    });

    expect(response.authorizationResponsePayload).toEqual({
      state: MOCK_STATE,
      vp_token: MOCK_VP_TOKEN,
    });
  });
});
