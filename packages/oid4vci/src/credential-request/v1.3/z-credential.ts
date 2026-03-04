import { z } from "zod";

import {
  credentialRequestRefiner,
  zBaseCredentialRequest,
} from "../z-base-credential-request";

/**
 * Proofs object schema for v1.3
 * Contains an array of JWTs (supports batch issuance)
 * proof_type is implicit (determined by the property name)
 */
export const zCredentialRequestProofs = z.object({
  jwt: z
    .array(z.string().min(1, "JWT must not be empty"))
    .min(1, "At least one JWT proof is required"),
});

export type CredentialRequestProofs = z.infer<typeof zCredentialRequestProofs>;

/**
 * Credential request schema for IT-Wallet v1.3
 *
 * Key changes from v1.0:
 * - Uses plural `proofs` object (not `proof`)
 * - proof_type field removed (implicit from structure)
 * - JWT is an array (supports batch issuance)
 * - JWT header includes `key_attestation` field
 */
export const zCredentialRequestV1_3 = zBaseCredentialRequest
  .extend({
    proofs: zCredentialRequestProofs.describe(
      "REQUIRED. Proof of possession of key material (contains array of JWTs for batch support).",
    ),
  })
  .superRefine((data, ctx) => {
    credentialRequestRefiner(data, ctx);
  });

export type CredentialRequestV1_3 = z.infer<typeof zCredentialRequestV1_3>;
