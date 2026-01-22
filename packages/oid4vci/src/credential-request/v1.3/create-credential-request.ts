import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";
import {
  ValidationError,
  dateToSeconds,
  parseWithErrorHandling,
} from "@openid4vc/utils";

import { Oid4vciError } from "../../errors";
import { CredentialRequestV1_3, zCredentialRequestV1_3 } from "./z-credential";

/**
 * Options for creating a credential request in IT-Wallet v1.3
 */
export interface CredentialRequestOptionsV1_3 {
  callbacks: Pick<CallbackContext, "signJwt">;
  clientId: string;
  credential_identifier: string;
  issuerIdentifier: string;
  /**
   * Wallet Unit Attestation (key attestation JWT)
   * REQUIRED in v1.3 - included in JWT proof header
   */
  keyAttestation: string;
  nonce: string;
  signer: JwtSignerJwk;
}

/**
 * Create a Credential Request for IT-Wallet v1.3
 *
 * Version 1.3.3 specifics:
 * - Returns plural `proofs` object with JWT array (batch support)
 * - proof_type field removed (implicit from structure)
 * - JWT header includes `key_attestation` field (Wallet Unit Attestation)
 *
 * @param options - Request options including keyAttestation
 * @returns Credential request for v1.3
 * @throws {ValidationError} When credential request validation fails
 * @throws {Oid4vciError} For other unexpected errors
 *
 * @example
 * const request = await createCredentialRequest({
 *   callbacks: { signJwt: mySignJwtCallback },
 *   clientId: "my-client-id",
 *   credential_identifier: "UniversityDegree",
 *   issuerIdentifier: "https://issuer.example.com",
 *   keyAttestation: "eyJ...", // Required in v1.3
 *   nonce: "c_nonce_value",
 *   signer: myJwtSigner
 * });
 * // Returns: { credential_identifier: "...", proofs: { jwt: ["..."] } }
 */
export const createCredentialRequest = async (
  options: CredentialRequestOptionsV1_3,
): Promise<CredentialRequestV1_3> => {
  try {
    const { signJwt } = options.callbacks;

    const proofJwt = await signJwt(options.signer, {
      header: {
        alg: options.signer.alg,
        jwk: options.signer.publicJwk,
        key_attestation: options.keyAttestation,
        typ: "openid4vci-proof+jwt",
      },
      payload: {
        aud: options.issuerIdentifier,
        iat: dateToSeconds(new Date()),
        iss: options.clientId,
        nonce: options.nonce,
      },
    });

    return parseWithErrorHandling(zCredentialRequestV1_3, {
      credential_identifier: options.credential_identifier,
      proofs: {
        jwt: [proofJwt.jwt], // Array for batch support
      },
    } satisfies CredentialRequestV1_3);
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }

    throw new Oid4vciError(
      `Unexpected error during create credential request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};
