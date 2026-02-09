import { z } from "zod";

/**
 * Schema for a single credential in the credentials array (v1.0.2)
 */
const CredentialObjectSchema = z.object({
  credential: z
    .string()
    .describe(
      "REQUIRED if lead_time and transaction_id are not present, otherwise it MUST NOT be present. Contains the issued Digital Credential. For dc+sd-jwt format: unencoded credential string. For mso_mdoc format: base64url-encoded CBOR-encoded IssuerSigned structure per ISO 18013-5.",
    ),
});

/**
 * Credential Response schema for IT Wallet v1.0.2
 *
 * Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.0.2/en/credential-issuer-endpoint.html#credential-response
 *
 * Response contains either:
 * - Immediate issuance: `credentials` (array)
 * - Deferred issuance: `lead_time` + `transaction_id`
 */
export const zCredentialResponseV1_0 = z
  .object({
    credentials: z
      .array(CredentialObjectSchema)
      .optional()
      .describe(
        "Conditional. Array of issued Digital Credentials as JSON objects with `credential` member containing encoded credential string. Present for immediate issuance (HTTP 200).",
      ),

    lead_time: z
      .number()
      .int()
      .positive()
      .optional()
      .describe(
        "REQUIRED for deferred flow. Duration in seconds before making a Deferred Credential Request.",
      ),

    notification_id: z
      .string()
      .optional()
      .describe(
        "OPTIONAL. Identifier for issued Credential included in subsequent Notification Request. Only present with credentials parameter.",
      ),

    transaction_id: z
      .string()
      .optional()
      .describe(
        "REQUIRED for deferred flow. Identifier for deferred issuance transaction; must be invalidated after Credential obtainment.",
      ),
  })
  .strict()
  .superRefine((data, ctx) => {
    const hasCredentials = data.credentials !== undefined;
    const hasLeadTime = data.lead_time !== undefined;
    const hasTransactionId = data.transaction_id !== undefined;

    // Enforce XOR: credentials vs (lead_time + transaction_id)
    if (hasCredentials && (hasLeadTime || hasTransactionId)) {
      ctx.addIssue({
        code: "custom",
        message:
          "credentials MUST NOT be present with deferred flow fields (lead_time/transaction_id)",
        path: ["credentials"],
      });
    }

    // For deferred flow, require both lead_time and transaction_id
    if (!hasCredentials) {
      if (!hasLeadTime || !hasTransactionId) {
        ctx.addIssue({
          code: "custom",
          message:
            "Both lead_time and transaction_id are REQUIRED when credentials is not present (deferred flow)",
          path: hasLeadTime ? ["transaction_id"] : ["lead_time"],
        });
      }
    }

    // notification_id must only exist if credentials is present
    if (!hasCredentials && data.notification_id) {
      ctx.addIssue({
        code: "custom",
        message: "notification_id MUST NOT be present if credentials is absent",
        path: ["notification_id"],
      });
    }
  });

export type CredentialResponseV1_0 = z.infer<typeof zCredentialResponseV1_0>;
