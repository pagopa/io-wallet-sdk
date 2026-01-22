import { z } from "zod";

/**
 * Credential Response schema (version-agnostic)
 * The response format is the same across v1.0 and v1.3
 */
export const zCredentialResponse = z
  .object({
    credentials: z
      .array(
        z.object({
          credential: z
            .string()
            .describe(
              "REQUIRED. Contains the issued Digital Credential. Depending on format, may be raw JWT or base64url-encoded CBOR structure.",
            ),
        }),
      )
      .optional(),
    lead_time: z.number().int().positive().optional(),
    notification_id: z.string().optional(),
    transaction_id: z.string().optional(),
  })
  .superRefine((data, ctx) => {
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

    if (!data.credentials && data.notification_id) {
      ctx.addIssue({
        code: "custom",
        message: "notification_id MUST NOT be present if credentials is absent",
        path: ["notification_id"],
      });
    }
  });

export type CredentialResponse = z.infer<typeof zCredentialResponse>;
