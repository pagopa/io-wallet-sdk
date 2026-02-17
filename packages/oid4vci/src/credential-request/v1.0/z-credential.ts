import { z } from "zod";

import {
  credentialRequestRefiner,
  zBaseCredentialRequest,
} from "../z-base-credential-request";

/**
 * Proof object schema for v1.0
 * Contains a JWT and explicit proof_type field
 */
export const zCredentialRequestProof = z.object({
  jwt: z.string().min(1, "JWT must not be empty"),
  proof_type: z.literal("jwt"), // MUST be "jwt"
});

export type CredentialRequestProof = z.infer<typeof zCredentialRequestProof>;

/**
 * Credential request schema for IT-Wallet v1.0
 *
 * Key characteristics:
 * - Uses singular `proof` object
 * - Explicit `proof_type` field (always "jwt")
 * - Single credential per request (no batch support)
 */
export const zCredentialRequestV1_0 = zBaseCredentialRequest
  .extend({
    proof: zCredentialRequestProof.describe(
      "REQUIRED. Proof of possession of key material (must contain proof_type=jwt and a jwt).",
    ),
  })
  .superRefine((data, ctx) => {
    credentialRequestRefiner(data, ctx);
  });

export type CredentialRequestV1_0 = z.infer<typeof zCredentialRequestV1_0>;
