import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";
import { dateToSeconds, parseWithErrorHandling } from "@openid4vc/utils";

import { Oid4vciError } from "../errors";
import { CredentialRequest, zCredentialRequest } from "./z-credential";

export interface CredentialRequestOptions {
  /**
   * Callbacks to use for signing proof
   */
  callbacks: Pick<CallbackContext, "signJwt">;

  /**
   * Client identifier of the OAuth2 Client making the Credential Request.
   */
  clientId: string;

  /**
   * This MUST be set with one of the value obtained in the credential_identifiers claim of the Token Response.
   */
  credential_identifier: string;

  /**
   * Identifier of the Credential Issuer, for ex: https://issuer.example.com.
   */
  issuerIdentifier: string;

  nonce: string;

  /**
   * The signer of the credential PoP JWT.
   */
  signer: JwtSignerJwk;
}

/**
 * Create a Credential Request.
 * @param options - Options to create the Credential Request
 * @returns The created Credential Request
 */
export const createCredentialRequest = async (
  options: CredentialRequestOptions,
): Promise<CredentialRequest> => {
  try {
    const { signJwt } = options.callbacks;
    const proofJwt = await signJwt(options.signer, {
      header: {
        alg: options.signer.alg,
        jwk: options.signer.publicJwk,
        typ: "openid4vci-proof+jwt",
      },
      payload: {
        aud: options.issuerIdentifier,
        iat: dateToSeconds(new Date()),
        iss: options.clientId,
        nonce: options.nonce,
      },
    });

    return parseWithErrorHandling(zCredentialRequest, {
      credential_identifier: options.credential_identifier,
      proof: {
        jwt: proofJwt.jwt,
        proof_type: "jwt",
      },
    } satisfies CredentialRequest);
  } catch (error) {
    throw new Oid4vciError(
      `Unexpected error during create credential request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};
