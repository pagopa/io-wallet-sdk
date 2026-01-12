import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";
import {
  ValidationError,
  dateToSeconds,
  parseWithErrorHandling,
} from "@openid4vc/utils";

import { Oid4vciError } from "../../errors";
import {
  CredentialRequestV1_0_2,
  zCredentialRequestV1_0_2,
} from "./z-credential";

/**
 * Options for creating a credential request in IT-Wallet v1.0.2
 */
export interface CredentialRequestOptionsV1_0_2 {
  callbacks: Pick<CallbackContext, "signJwt">;
  clientId: string;
  credential_identifier: string;
  issuerIdentifier: string;
  nonce: string;
  signer: JwtSignerJwk;
}

/**
 * Create a Credential Request for IT-Wallet v1.0.2
 *
 * Version 1.0.2 specifics:
 * - Returns singular `proof` object with explicit `proof_type` field
 * - JWT header does NOT include `key_attestation`
 * - Single credential per request (no batch support)
 *
 * @param options - Request options
 * @returns Credential request for v1.0.2
 * @throws {ValidationError} When credential request validation fails
 * @throws {Oid4vciError} For other unexpected errors
 *
 * @example
 * const request = await createCredentialRequest({
 *   callbacks: { signJwt: mySignJwtCallback },
 *   clientId: "my-client-id",
 *   credential_identifier: "UniversityDegree",
 *   issuerIdentifier: "https://issuer.example.com",
 *   nonce: "c_nonce_value",
 *   signer: myJwtSigner
 * });
 * // Returns: { credential_identifier: "...", proof: { jwt: "...", proof_type: "jwt" } }
 */
export const createCredentialRequest = async (
  options: CredentialRequestOptionsV1_0_2,
): Promise<CredentialRequestV1_0_2> => {
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

    return parseWithErrorHandling(zCredentialRequestV1_0_2, {
      credential_identifier: options.credential_identifier,
      proof: {
        jwt: proofJwt.jwt,
        proof_type: "jwt",
      },
    } satisfies CredentialRequestV1_0_2);
  } catch (error) {
    // Re-throw validation errors with full context for debugging
    if (error instanceof ValidationError) {
      throw error;
    }

    // Only wrap unexpected errors
    throw new Oid4vciError(
      `Unexpected error during create credential request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};
