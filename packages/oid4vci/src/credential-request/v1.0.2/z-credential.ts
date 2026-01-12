import { z } from "zod";

/**
 * Proof object schema for v1.0.2
 * Contains a JWT and explicit proof_type field
 */
const ProofSchema = z.object({
  jwt: z.string().min(1, "JWT must not be empty"),
  proof_type: z.literal("jwt"), // MUST be "jwt"
});

/**
 * Credential request schema for IT-Wallet v1.0.2
 *
 * Key characteristics:
 * - Uses singular `proof` object
 * - Explicit `proof_type` field (always "jwt")
 * - Single credential per request (no batch support)
 */
export const zCredentialRequestV1_0_2 = z
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

export type CredentialRequestV1_0_2 = z.infer<typeof zCredentialRequestV1_0_2>;

/**
 * Credential response schema for v1.0.2
 * Issuer returns single credential or deferred response
 */
const CredentialsSchema = z.array(
  z.object({
    credential: z
      .string()
      .describe(
        "REQUIRED. Contains the issued Digital Credential. Depending on format, may be raw JWT or base64url-encoded CBOR structure.",
      ),
  }),
);

export const zCredentialResponseV1_0_2 = z
  .object({
    credentials: CredentialsSchema.optional().describe(
      "REQUIRED if lead_time and transaction_id are not present. MUST NOT be present otherwise.",
    ),

    lead_time: z
      .number()
      .int()
      .positive()
      .optional()
      .describe(
        "REQUIRED if credentials is not present. MUST NOT be present otherwise.",
      ),

    notification_id: z
      .string()
      .optional()
      .describe("OPTIONAL. MUST NOT be present if credentials is not present."),

    transaction_id: z
      .string()
      .optional()
      .describe(
        "REQUIRED if credentials is not present. MUST NOT be present otherwise.",
      ),
  })
  .superRefine((data, ctx) => {
    // Enforce XOR: credentials vs (lead_time + transaction_id)
    if (data.credentials && (data.lead_time || data.transaction_id)) {
      ctx.addIssue({
        code: "custom",
        message:
          "credentials MUST NOT be present if lead_time or transaction_id is provided",
        path: ["credentials"],
      });
    }

    if (!data.credentials && (!data.lead_time || !data.transaction_id)) {
      ctx.addIssue({
        code: "custom",
        message:
          "If credentials is absent, both lead_time and transaction_id MUST be present",
        path: ["lead_time"],
      });
    }

    // notification_id must only exist if credentials is present
    if (!data.credentials && data.notification_id) {
      ctx.addIssue({
        code: "custom",
        message: "notification_id MUST NOT be present if credentials is absent",
        path: ["notification_id"],
      });
    }
  });

export type CredentialResponseV1_0_2 = z.infer<
  typeof zCredentialResponseV1_0_2
>;
