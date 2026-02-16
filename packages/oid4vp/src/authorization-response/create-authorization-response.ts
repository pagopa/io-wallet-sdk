import type {
  ItWalletCredentialVerifierMetadata,
  ItWalletCredentialVerifierMetadataV1_3,
} from "@pagopa/io-wallet-oid-federation";

import { CallbackContext, JweEncryptor, Jwk } from "@openid4vc/oauth2";
import { VpToken, extractEncryptionJwkFromJwks } from "@openid4vc/openid4vp";
import { encodeToBase64Url } from "@openid4vc/utils";

import {
  AuthorizationRequestObject,
  ClientIdPrefix,
  extractClientIdPrefix,
} from "../authorization-request";
import { CreateAuthorizationResponseError } from "../errors";
import { AuthorizationResponse } from "./z-authorization-response";

export interface CreateAuthorizationResponseOptions {
  /**
   * JARM encryption algorithm (JWE alg), should be one of the values supported by the verifier's metadata.
   * falls back to "ECDH-ES" if not provided.
   */
  authorization_encrypted_response_alg?: string;

  /**
   * JARM encryption encoding (JWE enc), should be one of the values supported by the verifier's metadata.
   * falls back to "A256GCM" if not provided.
   */
  authorization_encrypted_response_enc?: string;

  /**
   * Callbacks for authorization response generation
   */
  callbacks: Pick<CallbackContext, "encryptJwe" | "generateRandom">;

  /**
   * Presentation's Request Object
   */
  requestObject: AuthorizationRequestObject;

  /**
   * Relying Party metadata JWKS
   */
  rpJwks: Pick<
    ItWalletCredentialVerifierMetadata | ItWalletCredentialVerifierMetadataV1_3,
    "jwks"
  >;

  /**
   * Array containing the vp_tokens of the credentials
   * to present
   */
  vp_token: VpToken;
}

/**
 * Result of createAuthorizationResponse function
 * Contains the generated JARM payload and the encrypted response to send to the verifier
 */
export interface CreateAuthorizationResponseResult {
  authorizationResponsePayload: AuthorizationResponse;
  jarm: {
    encryptionJwk: Jwk;
    responseJwe: string;
  };
}

/**
 * Creates an encrypted JARM authorization response for OpenID4VP presentation.
 *
 * This function generates a JARM (JWT Secured Authorization Response Mode) response
 * containing the VP tokens from the wallet to the verifier.
 *
 * **Version Compatibility:**
 * - v1.0 metadata: JARM algorithms are read from rpJwks if not explicitly provided
 * - v1.3 metadata: JARM algorithms may be provided explicitly; when omitted, values are
 *   resolved from rpJwks or fall back to implementation defaults (e.g. ECDH-ES / A256GCM)
 *
 * @param options - Configuration for creating the authorization response
 * @param options.authorization_encrypted_response_alg - Optional JARM encryption algorithm (JWE alg). If omitted, falls back to "ECDH-ES".
 * @param options.authorization_encrypted_response_enc - Optional JARM encryption encoding (JWE enc). If omitted, the first value from metadata's encrypted_response_enc_values_supported is used, or falls back to "A256GCM".
 * @param options.callbacks - Cryptographic callbacks for JWE encryption
 * @param options.requestObject - The authorization request object to respond to
 * @param options.rpJwks - Relying Party JWKS with optional enc values (v1.0 or v1.3)
 * @param options.vp_token - Array of VP tokens to include in the response
 *
 * @returns An encrypted JARM authorization response (JWE compact serialization)
 *
 * @throws {CreateAuthorizationResponseError} If response generation or encryption fails
 */
export async function createAuthorizationResponse(
  options: CreateAuthorizationResponseOptions,
): Promise<CreateAuthorizationResponseResult> {
  try {
    const encryptionAlg: string =
      options.authorization_encrypted_response_alg ?? "ECDH-ES";

    const encryptionEnc: string =
      options.authorization_encrypted_response_enc ?? "A256GCM";

    // Determine which metadata to use based on client_id prefix
    const { requestObject } = options;
    const clientMetadata = requestObject.client_metadata;
    const clientIdPrefix = extractClientIdPrefix(requestObject.client_id);

    if (clientIdPrefix === ClientIdPrefix.X509_HASH && !clientMetadata) {
      throw new CreateAuthorizationResponseError(
        "clientMetadata is required when client_id uses x509_hash prefix",
      );
    }

    // When using OpenID Federation, client_metadata may be present in the request
    // but per the Italian specification most of its content should be ignored —
    // use rpJwks for encryption parameters instead.
    const effectiveClientMetadata =
      clientIdPrefix === ClientIdPrefix.OPENID_FEDERATION
        ? undefined
        : clientMetadata;

    const authorizationResponsePayload: AuthorizationResponse = {
      state: requestObject.state,
      vp_token: options.vp_token,
    };

    // Extract encryption JWK from effective metadata
    const encryptionJwks = effectiveClientMetadata
      ? effectiveClientMetadata.jwks
      : options.rpJwks.jwks;
    const encryptionJwk = extractEncryptionJwkFromJwks(encryptionJwks, {
      supportedAlgValues: [encryptionAlg],
    });
    if (!encryptionJwk) {
      throw new CreateAuthorizationResponseError(
        "No encryption JWK found in metadata",
      );
    }

    let enc: string;
    if (effectiveClientMetadata?.encrypted_response_enc_values_supported) {
      // Take first supported, or otherwise the first value
      enc =
        [encryptionEnc].find((e) =>
          effectiveClientMetadata.encrypted_response_enc_values_supported?.includes(
            e,
          ),
        ) ??
        effectiveClientMetadata.encrypted_response_enc_values_supported[0] ??
        encryptionEnc;
    } else {
      enc = encryptionEnc;
    }

    const alg = encryptionJwk.alg ?? encryptionAlg;

    const nonceBytes = await options.callbacks.generateRandom(32);

    const jweEncryptor: JweEncryptor = {
      alg,
      apu: encodeToBase64Url(nonceBytes),
      apv: encodeToBase64Url(requestObject.nonce),
      enc,
      method: "jwk",
      publicJwk: encryptionJwk,
    };

    const plaintext = JSON.stringify(authorizationResponsePayload);

    const { encryptionJwk: usedJwk, jwe } = await options.callbacks.encryptJwe(
      jweEncryptor,
      plaintext,
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
