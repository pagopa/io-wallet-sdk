/**
 * IT-Wallet v1.0.2 credential request implementation
 *
 * This module implements the credential request flow according to
 * Italian Wallet technical specifications version 1.0.2
 *
 * Key characteristics:
 * - Uses singular `proof` object with explicit `proof_type` field
 * - JWT proof does NOT include `key_attestation` in header
 * - Single credential per request (no batch support)
 */

export { createCredentialRequest } from "./create-credential-request";
export type { CredentialRequestOptionsV1_0_2 } from "./create-credential-request";
export { fetchCredentialResponse } from "./fetch-credential-response";
export type { FetchCredentialResponseOptionsV1_0_2 } from "./fetch-credential-response";
export * from "./z-credential";
