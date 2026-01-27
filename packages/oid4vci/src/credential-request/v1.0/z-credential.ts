import { z } from "zod";

/**
 * Proof object schema for v1.0
 * Contains a JWT and explicit proof_type field
 */
const ProofSchema = z.object({
  jwt: z.string().min(1, "JWT must not be empty"),
  proof_type: z.literal("jwt"), // MUST be "jwt"
});

/**
 * Credential request schema for IT-Wallet v1.0
 *
 * Key characteristics:
 * - Uses singular `proof` object
 * - Explicit `proof_type` field (always "jwt")
 * - Single credential per request (no batch support)
 */
export const zCredentialRequestV1_0 = z
  .object({
    credential_configuration_id: z
      .string()
      .optional()
      .describe(
        "REQUIRED if credential_identifiers param is absent. MUST NOT be used otherwise.",
      ),

    credential_identifier: z
      .string()
      .optional()
      .describe(
        "REQUIRED when Authorization Details of type openid_credential was returned. MUST NOT be used if credential_configuration_id is present.",
      ),

    proof: ProofSchema.describe(
      "REQUIRED. Proof of possession of key material (must contain proof_type=jwt and a jwt).",
    ),

    transaction_id: z
      .string()
      .optional()
      .describe(
        "REQUIRED only in case of deferred flow. MUST NOT be present in immediate flow.",
      ),
  })
  .superRefine((data, ctx) => {
    // Exclusive OR between credential_identifier and credential_configuration_id
    if (data.credential_identifier && data.credential_configuration_id) {
      ctx.addIssue({
        code: "custom",
        message:
          "credential_identifier and credential_configuration_id MUST NOT be used together",
        path: ["credential_identifier"],
      });
    }

    if (!data.credential_identifier && !data.credential_configuration_id) {
      ctx.addIssue({
        code: "custom",
        message:
          "One of credential_identifier or credential_configuration_id MUST be present",
        path: ["credential_identifier"],
      });
    }
  });

export type CredentialRequestV1_0 = z.infer<typeof zCredentialRequestV1_0>;
