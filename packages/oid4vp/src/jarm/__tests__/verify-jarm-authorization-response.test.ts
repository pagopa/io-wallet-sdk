import { CallbackContext } from "@pagopa/io-wallet-oauth2";
import { describe, expect, it } from "vitest";

import { Openid4vpAuthorizationRequestPayload } from "../../authorization-request/z-authorization-request";
import {
  JarmMode,
  verifyJarmAuthorizationResponse,
} from "../verify-jarm-authorization-response";

const encodeJwtPart = (value: unknown): string =>
  Buffer.from(JSON.stringify(value), "utf8")
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");

const createJwt = (options: {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature?: string;
}) =>
  `${encodeJwtPart(options.header)}.${encodeJwtPart(options.payload)}.${options.signature ?? "valid_signature"}`;

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

const now = new Date("2026-03-05T10:00:00.000Z");
const nowSeconds = Math.floor(now.getTime() / 1000);

const buildCallbacks = (
  options: { decryptedPayload?: string; verified?: boolean } = {},
): Pick<CallbackContext, "decryptJwe" | "verifyJwt"> => {
  const decryptJwe: CallbackContext["decryptJwe"] = async () => {
    if (options.decryptedPayload !== undefined) {
      return {
        decrypted: true as const,
        decryptionJwk: { kty: "EC" },
        payload: options.decryptedPayload,
      };
    }

    return { decrypted: false as const };
  };

  const verifyJwt: CallbackContext["verifyJwt"] = async () => {
    if (options.verified === false) {
      return { verified: false as const };
    }

    return { signerJwk: { kty: "EC" }, verified: true as const };
  };

  return {
    decryptJwe,
    verifyJwt,
  };
};

describe("verifyJarmAuthorizationResponse", () => {
  it("accepts a signed JARM response when claims and signature are valid", async () => {
    const callbacks = buildCallbacks();
    const jwt = createJwt({
      header: { alg: "ES256", kid: "test-kid" },
      payload: {
        aud: authorizationRequestPayload.client_id,
        exp: nowSeconds + 60,
        iss: authorizationRequestPayload.iss,
        state: authorizationRequestPayload.state,
      },
    });

    const result = await verifyJarmAuthorizationResponse({
      authorizationRequestPayload,
      callbacks,
      jarmAuthorizationResponseJwt: jwt,
      now,
    });

    expect(result.type).toBe(JarmMode.Signed);
    expect(result.issuer).toBe(authorizationRequestPayload.iss);
  });

  it("rejects signed JARM when aud does not match authorization request client_id", async () => {
    const callbacks = buildCallbacks();
    const jwt = createJwt({
      header: { alg: "ES256", kid: "test-kid" },
      payload: {
        aud: "unexpected-audience",
        exp: nowSeconds + 60,
        iss: authorizationRequestPayload.iss,
      },
    });

    await expect(
      verifyJarmAuthorizationResponse({
        authorizationRequestPayload,
        callbacks,
        jarmAuthorizationResponseJwt: jwt,
        now,
      }),
    ).rejects.toThrow(/contains 'aud' value/u);
  });

  it("rejects signed JARM when iss does not match authorization request iss", async () => {
    const callbacks = buildCallbacks();
    const jwt = createJwt({
      header: { alg: "ES256", kid: "test-kid" },
      payload: {
        aud: authorizationRequestPayload.client_id,
        exp: nowSeconds + 60,
        iss: "https://unexpected-issuer.example.org",
      },
    });

    await expect(
      verifyJarmAuthorizationResponse({
        authorizationRequestPayload,
        callbacks,
        jarmAuthorizationResponseJwt: jwt,
        now,
      }),
    ).rejects.toThrow(/contains 'iss' value/u);
  });

  it("rejects signed JARM when exp is in the past", async () => {
    const callbacks = buildCallbacks();
    const jwt = createJwt({
      header: { alg: "ES256", kid: "test-kid" },
      payload: {
        aud: authorizationRequestPayload.client_id,
        exp: nowSeconds - 1,
        iss: authorizationRequestPayload.iss,
      },
    });

    await expect(
      verifyJarmAuthorizationResponse({
        authorizationRequestPayload,
        callbacks,
        jarmAuthorizationResponseJwt: jwt,
        now,
      }),
    ).rejects.toThrow("Jarm Auth Response has expired.");
  });

  it("rejects signed JARM when nbf is in the future", async () => {
    const callbacks = buildCallbacks();
    const jwt = createJwt({
      header: { alg: "ES256", kid: "test-kid" },
      payload: {
        aud: authorizationRequestPayload.client_id,
        exp: nowSeconds + 120,
        iss: authorizationRequestPayload.iss,
        nbf: nowSeconds + 60,
      },
    });

    await expect(
      verifyJarmAuthorizationResponse({
        authorizationRequestPayload,
        callbacks,
        jarmAuthorizationResponseJwt: jwt,
        now,
      }),
    ).rejects.toThrow("Jarm Auth Response is not active yet.");
  });

  it("accepts an encrypted-only JARM response when the outer JWE header contains kid", async () => {
    const callbacks = buildCallbacks({
      decryptedPayload: JSON.stringify({
        iss: authorizationRequestPayload.iss,
        state: authorizationRequestPayload.state,
        vp_token: { presentation: "token" },
      }),
    });

    const result = await verifyJarmAuthorizationResponse({
      authorizationRequestPayload,
      callbacks,
      jarmAuthorizationResponseJwt: createJwe({
        alg: "ECDH-ES",
        enc: "A256GCM",
        kid: "enc-kid",
      }),
      now,
    });

    expect(result.type).toBe(JarmMode.Encrypted);
  });

  it("rejects encrypted-only JARM when the outer JWE header is missing kid", async () => {
    const callbacks = buildCallbacks({
      decryptedPayload: JSON.stringify({
        iss: authorizationRequestPayload.iss,
        state: authorizationRequestPayload.state,
        vp_token: { presentation: "token" },
      }),
    });

    await expect(
      verifyJarmAuthorizationResponse({
        authorizationRequestPayload,
        callbacks,
        jarmAuthorizationResponseJwt: createJwe({
          alg: "ECDH-ES",
          enc: "A256GCM",
        }),
        now,
      }),
    ).rejects.toThrow();
  });

  it("rejects signed and encrypted JARM when the outer JWE header is missing kid", async () => {
    const callbacks = buildCallbacks({
      decryptedPayload: createJwt({
        header: { alg: "ES256", kid: "test-kid" },
        payload: {
          aud: authorizationRequestPayload.client_id,
          exp: nowSeconds + 60,
          iss: authorizationRequestPayload.iss,
          state: authorizationRequestPayload.state,
          vp_token: { presentation: "token" },
        },
      }),
    });

    await expect(
      verifyJarmAuthorizationResponse({
        authorizationRequestPayload,
        callbacks,
        jarmAuthorizationResponseJwt: createJwe({
          alg: "ECDH-ES",
          enc: "A256GCM",
        }),
        now,
      }),
    ).rejects.toThrow();
  });
});
