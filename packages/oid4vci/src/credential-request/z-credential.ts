import { z } from "zod";

const CredentialsSchema = z.array(
  z.object({
    credential: z
      .string()
      .describe(
        "REQUIRED. Contains the issued Digital Credential. Depending on format, may be raw JWT or base64url-encoded CBOR structure.",
      ),
  }),
);

/**
 * Credential Response schema (version-agnostic)
 * The response format is the same across v1.0 and v1.3
 */
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
