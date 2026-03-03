import { type JwtSignerJwk } from "@openid4vc/oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ValidationError,
  dateToSeconds,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { Oid4vciError } from "../../errors";
import { BaseCredentialRequestOptions } from "../types";
import { CredentialRequestV1_3, zCredentialRequestV1_3 } from "./z-credential";

/**
 * Options for creating a credential request with v1.3
 * Requires keyAttestation parameter
 */
export interface CredentialRequestOptionsV1_3
  extends BaseCredentialRequestOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>;
  keyAttestation: string; // Required in v1.3
  signers: JwtSignerJwk[]; // Multiple signers to support batch issuance
}

/**
 * Create a Credential Request for IT-Wallet v1.3
 *
 * Version 1.3 specifics:
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
 *   signers: [myJwtSigner]
 * });
 * // Returns: { credential_identifier: "...", proofs: { jwt: ["..."] } }
 */
export const createCredentialRequest = async (
  options: CredentialRequestOptionsV1_3,
): Promise<CredentialRequestV1_3> => {
  try {
    const { signJwt } = options.callbacks;

    const proofJwts = await Promise.all(
      options.signers.map((signer) =>
        signJwt(signer, {
          header: {
            alg: signer.alg,
            jwk: signer.publicJwk,
            key_attestation: options.keyAttestation,
            typ: "openid4vci-proof+jwt",
          },
          payload: {
            aud: options.issuerIdentifier,
            iat: dateToSeconds(new Date()),
            iss: options.clientId,
            nonce: options.nonce,
          },
        }),
      ),
    );

    return parseWithErrorHandling(zCredentialRequestV1_3, {
      credential_identifier: options.credential_identifier,
      proofs: {
        jwt: proofJwts.map((proofJwt) => proofJwt.jwt), // Array for batch support
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
