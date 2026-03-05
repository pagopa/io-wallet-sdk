import {
  CallbackContext,
  HashAlgorithm,
  type JwtSignerJwk,
  calculateJwkThumbprint,
} from "@openid4vc/oauth2";
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
  callbacks: Pick<CallbackContext, "hash" | "signJwt">;
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>;
  keyAttestation: string; // Required in v1.3
  /**
   * The maximum size for a single credential batch issuance request.
   * It is extracted from the Issuer Metadata: `batch_credential_issuance.batch_size`.
   */
  maxBatchSize?: number;
  /**
   * The list of signers to generate JWT proofs.
   * Multiple unique signers must be used for batch issuance.
   */
  signers: JwtSignerJwk[];
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
 *   callbacks: { signJwt: mySignJwtCallback, hash: myHashCallback },
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
    const { maxBatchSize, signers } = options;

    if (signers.length === 0) {
      throw new ValidationError("At least one signer is required");
    }

    if (maxBatchSize !== undefined) {
      if (!Number.isInteger(maxBatchSize) || maxBatchSize <= 0) {
        throw new ValidationError(
          "Invalid maxBatchSize: it must be a positive integer",
        );
      }

      if (signers.length > maxBatchSize) {
        throw new ValidationError(
          "The number of provided signers exceeds the maximum batch size allowed",
        );
      }
    }

    const { hash, signJwt } = options.callbacks;

    // Ensure all keys are unique for batch issuance
    if (signers.length > 1) {
      const allThumbprints = await Promise.all(
        signers.map((signer) =>
          calculateJwkThumbprint({
            hashAlgorithm: HashAlgorithm.Sha256,
            hashCallback: hash,
            jwk: signer.publicJwk,
          }),
        ),
      );
      const uniqueThumbprints = new Set(allThumbprints);
      if (uniqueThumbprints.size !== allThumbprints.length) {
        throw new ValidationError(
          "Found multiple signers with the same JWK: each JWT proof must be unique and linked to a different credential key pair",
        );
      }
    }

    const proofJwts = await Promise.all(
      signers.map((signer) =>
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
