import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";
import { CreateOpenid4vpAuthorizationResponseResult } from "@openid4vc/openid4vp";
import { addSecondsToDate, dateToSeconds } from "@openid4vc/utils";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";
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

const mockSigner: JwtSignerJwk = {
  alg: "ES256",
  method: "jwk",
  publicJwk: {
    crv: "P-256",
    kid: "testtesttest",
    kty: "EC",
    x: "...",
    y: "...",
  },
};

const MOCK_VP_TOKEN = ["vp_token1"];
const MOCK_STATE = "TEST_STATE";
const MOCK_WALLET_CLIENT_ID = "TEST_CLIENT";
const MOCK_RP_CLIENT_ID = "TEST_RP_CLIENT";
const MOCK_NONCE = "TEST_NONCE";
const REQOBJ_MOCK_NONCE = "REQ_TEST_NONCE";

const mockEncryptJwe = vi.fn((encrytor, data) => ({
  encryptionJwk: encrytor.publicJwk,
  jwe: `${data}_ENCRYPTED`,
}));

const callbacks: Pick<
  CallbackContext,
  "encryptJwe" | "fetch" | "generateRandom" | "signJwt"
> = {
  encryptJwe: mockEncryptJwe,
  fetch: vi.fn(),
  generateRandom: () => new Uint8Array(Buffer.from(MOCK_NONCE)),
  signJwt: (signer, { header, payload }) => {
    if (signer.method === "jwk") {
      return {
        jwt: `${Base64.encode(JSON.stringify(header), true)}.${Base64.encode(JSON.stringify(payload), true)}.signature`,
        signerJwk: signer.publicJwk,
      };
    } else throw new Error();
  },
};

const TEN_MINUTES = dateToSeconds(addSecondsToDate(new Date(), 60 * 10));
const ENCODED_NONCE = Base64.encode(MOCK_NONCE, true);
const REQOBJ_ENCODED_NONCE = Base64.encode(REQOBJ_MOCK_NONCE, true);

beforeEach(() => {
  vi.resetAllMocks();
});

describe("createAuthorizationResponseTests", () => {
  it("should create an encrypted and signed authorization response successfully", async () => {
    const response = await createAuthorizationResponse({
      callbacks,
      client_id: MOCK_WALLET_CLIENT_ID,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        response_mode: "direct_post.jwt",
        response_type: "vp_token",
        state: MOCK_STATE,
      },
      rpMetadata: mockRpMetadata,
      signer: mockSigner,
      vp_token: MOCK_VP_TOKEN,
    });

    expect(response.jarm?.responseJwt).toMatch(/.*\..*\.signature_ENCRYPTED/);
    expect(response.authorizationResponsePayload).toEqual<
      CreateOpenid4vpAuthorizationResponseResult["authorizationResponsePayload"]
    >({
      aud: MOCK_RP_CLIENT_ID,
      exp: TEN_MINUTES,
      iss: MOCK_WALLET_CLIENT_ID,
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

  it("should create an encrypted and signed authorization response successfully passing the custom expiration", async () => {
    const customExp = dateToSeconds(addSecondsToDate(new Date(), 60 * 60)); // 1h

    const response = await createAuthorizationResponse({
      callbacks,
      client_id: MOCK_WALLET_CLIENT_ID,
      exp: customExp,
      requestObject: {
        client_id: MOCK_RP_CLIENT_ID,
        nonce: REQOBJ_MOCK_NONCE,
        response_mode: "direct_post.jwt",
        response_type: "vp_token",
        state: MOCK_STATE,
      },
      rpMetadata: mockRpMetadata,
      signer: mockSigner,
      vp_token: MOCK_VP_TOKEN,
    });

    expect(response.authorizationResponsePayload).toMatchObject({
      exp: customExp,
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
        client_id: MOCK_WALLET_CLIENT_ID,
        requestObject: {
          client_id: MOCK_RP_CLIENT_ID,
          nonce: REQOBJ_MOCK_NONCE,
          response_mode: "direct_post.jwt",
          response_type: "vp_token",
          state: MOCK_STATE,
        },
        rpMetadata: rpMetadataWithoutKeys,
        signer: mockSigner,
        vp_token: MOCK_VP_TOKEN,
      }),
    ).rejects.toThrow(CreateAuthorizationResponseError);
  });
});
