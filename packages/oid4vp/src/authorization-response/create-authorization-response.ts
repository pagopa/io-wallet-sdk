import type {
  ItWalletCredentialVerifierMetadata,
  ItWalletCredentialVerifierMetadataV1_3,
} from "@pagopa/io-wallet-oid-federation";

import { CallbackContext, JwtSigner } from "@openid4vc/oauth2";
import {
  CreateOpenid4vpAuthorizationResponseOptions,
  VpToken,
  createOpenid4vpAuthorizationResponse,
} from "@openid4vc/openid4vp";
import { addSecondsToDate, dateToSeconds } from "@openid4vc/utils";

import { AuthorizationRequestObject } from "../authorization-request";
import { CreateAuthorizationResponseError } from "../errors";

type JarmServerMetadata = NonNullable<
  CreateOpenid4vpAuthorizationResponseOptions["jarm"]
>["serverMetadata"];

export interface CreateAuthorizationResponseOptions {
  /**
   * JARM encryption algorithm (JWE alg)
   *
   * falls back to rpMetadata.authorization_encrypted_response_alg if not provided.
   */
  authorization_encrypted_response_alg?: string;

  /**
   * JARM encryption encoding (JWE enc)
   *
   * falls back to rpMetadata.authorization_encrypted_response_enc if not provided.
   */
  authorization_encrypted_response_enc?: string;

  /**
   * JARM signing algorithm (JWS alg)
   *
   * falls back to rpMetadata.authorization_signed_response_alg if not provided.
   */
  authorization_signed_response_alg?: string;

  /**
   * Callbacks for authorization response generation
   */
  callbacks: Pick<
    CallbackContext,
    "encryptJwe" | "fetch" | "generateRandom" | "signJwt"
  >;

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
   * OpenID Federation Relying Party metadata
   *
   * Supports both v1.0 and v1.3 metadata structures:
   * - v1.0: Contains JARM algorithm fields directly
   * - v1.3: Contains encrypted_response_enc_values_supported, requires explicit JARM parameters
   */
  rpMetadata:
    | ItWalletCredentialVerifierMetadata
    | ItWalletCredentialVerifierMetadataV1_3;

  /**
   * Signer created from the Wallet Instance's private key
   * If not provided, the authorization payload won't be signed
   */
  signer?: JwtSigner;

  /**
   * Array containing the vp_tokens of the credentials
   * to present
   */
  vp_token: VpToken;
}

/**
 * Creates a signed and encrypted authorization response for OpenID4VP presentation.
 *
 * This function generates a JARM (JWT Secured Authorization Response Mode) response
 * containing the VP tokens from the wallet to the verifier.
 *
 * **Version Compatibility:**
 * - v1.0 metadata: JARM algorithms are read from rpMetadata if not explicitly provided
 * - v1.3 metadata: JARM algorithms may be provided explicitly; when omitted, values are
 *   resolved from rpMetadata or fall back to implementation defaults (e.g. ECDH-ES / A256GCM / ES256)
 *
 * @param options - Configuration for creating the authorization response
 * @param options.authorization_encrypted_response_alg - Optional JARM encryption algorithm (JWE alg). For v1.3, if omitted, it is derived from rpMetadata or falls back to a default (e.g. ECDH-ES).
 * @param options.authorization_encrypted_response_enc - Optional JARM encryption encoding (JWE enc). For v1.3, if omitted, it is derived from rpMetadata or falls back to a default (e.g. A256GCM).
 * @param options.authorization_signed_response_alg - Optional JARM signing algorithm (JWS alg). For v1.3, if omitted, it is derived from rpMetadata or falls back to a default (e.g. ES256).
 * @param options.callbacks - Cryptographic callbacks for JWT operations
 * @param options.client_id - Thumbprint of the JWK in the cnf Wallet Attestation
 * @param options.exp - Optional JWT expiration time in seconds (default: 10 minutes)
 * @param options.requestObject - The authorization request object to respond to
 * @param options.rpMetadata - OpenID Federation Relying Party metadata (v1.0 or v1.3)
 * @param options.signer - Optional signer for JWT signing. If omitted, response won't be signed
 * @param options.vp_token - Array of VP tokens to include in the response
 *
 * @returns A signed and/or encrypted authorization response
 *
 * @throws {CreateAuthorizationResponseError} If response generation, encryption, or signing fails
 */
export async function createAuthorizationResponse(
  options: CreateAuthorizationResponseOptions,
) {
  try {
    const openid_credential_verifier = options.rpMetadata;

    const encryptionAlg: string =
      options.authorization_encrypted_response_alg ??
      ("authorization_encrypted_response_alg" in openid_credential_verifier
        ? (openid_credential_verifier.authorization_encrypted_response_alg as string)
        : "ECDH-ES"); // Default encryption algorithm (works with EC keys)

    const encryptionEnc: string =
      options.authorization_encrypted_response_enc ??
      ("authorization_encrypted_response_enc" in openid_credential_verifier
        ? (openid_credential_verifier.authorization_encrypted_response_enc as string)
        : "encrypted_response_enc_values_supported" in
            openid_credential_verifier
          ? (openid_credential_verifier
              .encrypted_response_enc_values_supported[0] as string)
          : "A256GCM"); // Default encryption encoding

    const signingAlg: string =
      options.authorization_signed_response_alg ??
      ("authorization_signed_response_alg" in openid_credential_verifier
        ? (openid_credential_verifier.authorization_signed_response_alg as string)
        : "ES256"); // Default signing algorithm

    const serverMetadata: JarmServerMetadata = {
      authorization_encryption_alg_values_supported: [encryptionAlg],
      authorization_encryption_enc_values_supported: [encryptionEnc],
      authorization_signing_alg_values_supported: [signingAlg],
    };

    // NOTE: This method sets the state in the Authorization Response
    //       using the corresponding value in the Request Object
    return await createOpenid4vpAuthorizationResponse({
      authorizationRequestPayload: options.requestObject,
      authorizationResponsePayload: {
        vp_token: options.vp_token,
      },
      callbacks: options.callbacks,
      clientMetadata: openid_credential_verifier,
      jarm: {
        audience: options.requestObject.client_id,
        authorizationServer: options.client_id,
        encryption: {
          nonce: new TextDecoder().decode(
            await options.callbacks.generateRandom(32),
          ),
        },
        expiresInSeconds:
          options.exp ?? dateToSeconds(addSecondsToDate(new Date(), 60 * 10)), // default: 10 minutes
        jwtSigner: options.signer,
        serverMetadata,
      },
    });
  } catch (error) {
    throw new CreateAuthorizationResponseError(
      `Unexpected error during authorization response creation parsing: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
