import { z } from "zod";

// Proof object schema
const ProofSchema = z.object({
  jwt: z.string().min(1, "JWT must not be empty"),
  proof_type: z.literal("jwt"), // MUST be "jwt"
});

export const zCredentialRequest = z
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

export type CredentialRequest = z.infer<typeof zCredentialRequest>;

const CredentialsSchema = z.object({
  credential: z
    .string()
    .min(1, "credential must not be empty")
    .describe(
      "REQUIRED. Contains the issued Digital Credential. Depending on format, may be raw JWT or base64url-encoded CBOR structure.",
    ),
});

export const zCredentialResponse = z
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

export type CredentialResponse = z.infer<typeof zCredentialResponse>;
