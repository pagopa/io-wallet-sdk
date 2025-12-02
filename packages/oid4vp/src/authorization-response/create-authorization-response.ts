import { CallbackContext, JwtSigner } from "@openid4vc/oauth2";
import {
  CreateOpenid4vpAuthorizationResponseOptions,
  VpToken,
  createOpenid4vpAuthorizationResponse,
} from "@openid4vc/openid4vp";
import { addSecondsToDate, dateToSeconds } from "@openid4vc/utils";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

import { AuthorizationRequestObject } from "../authorization-request";
import { CreateAuthorizationResponseError } from "../errors";

type JarmServerMetadata = NonNullable<
  CreateOpenid4vpAuthorizationResponseOptions["jarm"]
>["serverMetadata"];

export interface CreateAuthorizationResponseOptions {
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
   */
  rpMetadata: ItWalletCredentialVerifierMetadata;

  /**
   * Signer created from the Wallet Instance's private key
   */
  signer: JwtSigner;

  /**
   * Array containing the vp_tokens of the credentials
   * to present
   */
  vp_token: VpToken;
}

/**
 * This method receives the RequestObject, its resolved VP Tokens and other necessary cryptographic and configuration data
 * and returns a signed and encrypted Presentation Response
 * @param options {@link CreateAuthorizationResponseOptions}
 * @returns An {@link CreateOpenid4vpAuthorizationResponseResult} representing
 *          the encrypted and signed Presentation Response to the corresponding {@link AuthorizationRequestObject}
 * @throws An {@link CreateAuthorizationResponseError} in case of unexpected errors during response generation,
 *         encryption, or signing
 */
export async function createAuthorizationResponse(
  options: CreateAuthorizationResponseOptions,
) {
  try {
    const openid_credential_verifier = options.rpMetadata;

    const serverMetadata: JarmServerMetadata = {
      authorization_encryption_alg_values_supported: [
        openid_credential_verifier.authorization_encrypted_response_alg,
      ],
      authorization_encryption_enc_values_supported: [
        openid_credential_verifier.authorization_encrypted_response_enc,
      ],
      authorization_signing_alg_values_supported: [
        openid_credential_verifier.authorization_signed_response_alg,
      ],
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
