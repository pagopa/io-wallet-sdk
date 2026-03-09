import { CallbackContext } from "@pagopa/io-wallet-oauth2";
import { describe, expect, it } from "vitest";

import { Openid4vpAuthorizationRequestPayload } from "../../authorization-request";
import { parseJarmAuthorizationResponse } from "../parse-jarm-authorization-response";

const encodeJwtPart = (value: unknown): string =>
  Buffer.from(JSON.stringify(value), "utf8")
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");

const createJwe = (header: Record<string, unknown>) =>
  `${encodeJwtPart(header)}.encrypted_key.iv.ciphertext.tag`;

const authorizationRequestPayload: Openid4vpAuthorizationRequestPayload = {
  client_id: "openid_federation:https://verifier.example.org",
  dcql_query: {},
  iss: "https://verifier.example.org",
  nonce: "nonce-123",
  response_mode: "direct_post.jwt",
  response_type: "vp_token",
  response_uri: "https://wallet.example.org/cb",
  state: "state-123",
};

const buildCallbacks = (
  decryptedPayload: string,
): Pick<CallbackContext, "decryptJwe" | "verifyJwt"> => ({
  decryptJwe: async () => ({
    decrypted: true as const,
    decryptionJwk: { kty: "EC" },
    payload: decryptedPayload,
  }),
  verifyJwt: async () => ({
    signerJwk: { kty: "EC" },
    verified: true as const,
  }),
});

describe("parseJarmAuthorizationResponse", () => {
  it("parses encrypted-only JARM when the outer JWE header contains kid", async () => {
    const result = await parseJarmAuthorizationResponse({
      authorizationRequestPayload,
      callbacks: buildCallbacks(
        JSON.stringify({
          iss: authorizationRequestPayload.iss,
          state: authorizationRequestPayload.state,
          vp_token: { presentation: "token" },
        }),
      ),
      jarmResponseJwt: createJwe({
        alg: "ECDH-ES",
        enc: "A256GCM",
        kid: "enc-kid",
      }),
    });

    expect(result.jarm?.jarmHeader.kid).toBe("enc-kid");
    expect(result.authorizationResponsePayload.vp_token).toEqual({
      presentation: "token",
    });
  });

  it("rejects encrypted-only JARM when the outer JWE header is missing kid", async () => {
    await expect(
      parseJarmAuthorizationResponse({
        authorizationRequestPayload,
        callbacks: buildCallbacks(
          JSON.stringify({
            iss: authorizationRequestPayload.iss,
            state: authorizationRequestPayload.state,
            vp_token: { presentation: "token" },
          }),
        ),
        jarmResponseJwt: createJwe({
          alg: "ECDH-ES",
          enc: "A256GCM",
        }),
      }),
    ).rejects.toThrow();
  });
});
