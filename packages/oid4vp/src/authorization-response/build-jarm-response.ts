import type { JwkSet } from "@pagopa/io-wallet-oauth2";

import { CallbackContext, JweEncryptor } from "@pagopa/io-wallet-oauth2";
import { encodeToBase64Url } from "@pagopa/io-wallet-utils";

import type { CreateAuthorizationResponseResult } from "./types";

import { Openid4vpAuthorizationRequestPayload } from "../authorization-request/z-authorization-request";
import { CreateAuthorizationResponseError } from "../errors";
import { extractEncryptionJwkFromJwks } from "../jarm/jarm-extract-jwks";
import { VpToken } from "../vp-token/z-vp-token";

export interface BuildJarmResponseOptions {
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;
  callbacks: Pick<CallbackContext, "encryptJwe" | "generateRandom">;
  encValuesSupported: string[] | undefined;
  encryptionJwks: JwkSet;
  requestObject: Pick<Openid4vpAuthorizationRequestPayload, "nonce" | "state">;
  vp_token: VpToken;
}

function resolveEncValue(
  supported: string[] | undefined,
  requested: string | undefined,
  fallback: string,
): string {
  if (!supported) return requested ?? fallback;
  return (
    supported.find((e) => e === requested) ??
    supported[0] ??
    requested ??
    fallback
  );
}

/**
 * Shared core: resolves enc/alg, encrypts the VP token into a JARM JWE, and returns the result.
 * Callers are responsible for resolving `encryptionJwks` and `encValuesSupported`
 * according to their version-specific metadata rules before invoking this function.
 */
export async function buildJarmResponse(
  options: BuildJarmResponseOptions,
): Promise<CreateAuthorizationResponseResult> {
  try {
    const encryptionAlg =
      options.authorization_encrypted_response_alg ?? "ECDH-ES";
    const encryptionEnc =
      options.authorization_encrypted_response_enc ?? "A256GCM";

    const authorizationResponsePayload = {
      state: options.requestObject.state,
      vp_token: options.vp_token,
    };

    const encryptionJwk = extractEncryptionJwkFromJwks(options.encryptionJwks, {
      supportedAlgValues: [encryptionAlg],
    });
    if (!encryptionJwk) {
      throw new CreateAuthorizationResponseError(
        "No encryption JWK found in metadata",
      );
    }

    const enc = resolveEncValue(
      options.encValuesSupported,
      options.authorization_encrypted_response_enc,
      encryptionEnc,
    );

    const alg =
      options.authorization_encrypted_response_alg ??
      encryptionJwk.alg ??
      "ECDH-ES";

    const nonceBytes = await options.callbacks.generateRandom(32);

    const jweEncryptor: JweEncryptor = {
      alg,
      apu: encodeToBase64Url(nonceBytes),
      apv: encodeToBase64Url(options.requestObject.nonce),
      enc,
      method: "jwk",
      publicJwk: encryptionJwk,
    };

    const { encryptionJwk: usedJwk, jwe } = await options.callbacks.encryptJwe(
      jweEncryptor,
      JSON.stringify(authorizationResponsePayload),
    );

    return {
      authorizationResponsePayload,
      jarm: {
        encryptionJwk: usedJwk,
        responseJwe: jwe,
      },
    };
  } catch (error) {
    if (error instanceof CreateAuthorizationResponseError) {
      throw error;
    }
    throw new CreateAuthorizationResponseError(
      `Unexpected error during authorization response creation: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
