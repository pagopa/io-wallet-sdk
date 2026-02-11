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
   * Thumbprint of the JWK in the cnf Wallet Attestation
   */
  client_id: string;

  /**
   * Optional expiration of the Authorization Response JWT, defaults to 10 minutes
   */
  exp?: number;

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
 * Contains the generated JARM payload and the encrypted JWT response to send to the verifier
 */
export interface CreateAuthorizationResponseResult {
  authorizationResponsePayload: AuthorizationResponse;
  jarm: {
    encryptionJwk: Jwk;
    responseJwt: string;
  };
}

/**
 * Creates a signed and encrypted authorization response for OpenID4VP presentation.
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
 * @param options.authorization_encrypted_response_alg - Optional JARM encryption algorithm (JWE alg). For v1.3, if omitted, it is derived from rpJwks or falls back to a default (e.g. ECDH-ES).
 * @param options.authorization_encrypted_response_enc - Optional JARM encryption encoding (JWE enc). For v1.3, if omitted, it is derived from rpJwks or falls back to a default (e.g. A256GCM).
 * @param options.callbacks - Cryptographic callbacks for JWT operations
 * @param options.client_id - Thumbprint of the JWK in the cnf Wallet Attestation
 * @param options.exp - Optional JWT expiration time in seconds (default: 10 minutes)
 * @param options.requestObject - The authorization request object to respond to
 * @param options.rpJwks - OpenID Federation Relying Party JWKS (v1.0 or v1.3)
 * @param options.signer - Optional signer for JWT signing. If omitted, response won't be signed
 * @param options.vp_token - Array of VP tokens to include in the response
 *
 * @returns A signed and/or encrypted authorization response
 *
 * @throws {CreateAuthorizationResponseError} If response generation, encryption, or signing fails
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

    if (clientIdPrefix === ClientIdPrefix.OPENID_FEDERATION && clientMetadata) {
      throw new CreateAuthorizationResponseError(
        "clientMetadata is not required when client_id uses openid_federation prefix",
      );
    }

    const authorizationResponsePayload: AuthorizationResponse = {
      state: requestObject.state,
      vp_token: options.vp_token,
    };

    // Extract encryption JWK from effective metadata
    const encryptionJwks = clientMetadata
      ? clientMetadata.jwks
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
    if (clientMetadata?.encrypted_response_enc_values_supported) {
      // Take first supported, or otherwise the first value
      enc =
        [encryptionEnc].find((e) =>
          clientMetadata.encrypted_response_enc_values_supported?.includes(e),
        ) ??
        clientMetadata.encrypted_response_enc_values_supported[0] ??
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
        responseJwt: jwe,
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
