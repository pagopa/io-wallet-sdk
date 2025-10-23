import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";

import { CredentialRequest, zCredentialRequest } from "./z-credential";
import { Oid4vciError } from "../errors";
import { parseWithErrorHandling } from "@openid4vc/utils";

export interface CredentialRequestOptions {
  /**
   * Identifier of the Credential Issuer.
   */
  audience: string;

  /**
   * Callbacks to use for signing prood
   */
  callbacks: Pick<CallbackContext, "signJwt">;

  /**
   * This MUST be set with one of the value obtained in the credential_identifiers claim of the Token Response.
   */
  credential_identifier: string;

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
        aud: options.audience,
        iat: Math.floor(Date.now() / 1000),
        iss: options.audience, //?
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
