/**
 * IT-Wallet v1.3.3 credential request implementation
 *
 * This module implements the credential request flow according to
 * Italian Wallet technical specifications version 1.3.3
 *
 * Key changes from v1.0.2:
 * - Uses plural `proofs` object (not `proof`)
 * - proof_type field removed (implicit from structure)
 * - JWT is an array (supports batch issuance)
 * - JWT header includes `key_attestation` field (Wallet Unit Attestation)
 */

export { createCredentialRequest } from "./create-credential-request";
export type { CredentialRequestOptionsV1_3_3 } from "./create-credential-request";
export * from "./z-credential";
