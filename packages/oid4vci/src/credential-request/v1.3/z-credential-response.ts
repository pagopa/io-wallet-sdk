import { z } from "zod";

/**
 * Schema for a single credential in the credentials array (v1.3.3)
 */
const CredentialObjectSchema = z.object({
  credential: z
    .string()
    .describe(
      "REQUIRED if interval and transaction_id are not present, otherwise it MUST NOT be present. Contains the issued Digital Credential. For dc+sd-jwt format: unencoded credential string. For mso_mdoc format: base64url-encoded CBOR-encoded IssuerSigned structure per ISO 18013-5.",
    ),
});

/**
 * Credential Response schema for IT Wallet v1.3.3
 *
 * Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/credential-issuer-endpoint.html#credential-response
 *
 * Response contains either:
 * - Immediate issuance (HTTP 200): `credentials` (array)
 * - Deferred issuance (HTTP 202): `interval` + `transaction_id`
 */
export const zCredentialResponseV1_3 = z
  .object({
    credentials: z
      .array(CredentialObjectSchema)
      .optional()
      .describe(
        "Conditional. Array of issued Digital Credentials as JSON objects with `credential` member containing encoded credential string. Present for immediate issuance (HTTP 200).",
      ),

    interval: z
      .number()
      .int()
      .positive()
      .optional()
      .describe(
        "Conditional. Time in seconds to wait before retry. Present for deferred flow (HTTP 202).",
      ),

    notification_id: z
      .string()
      .optional()
      .describe(
        "OPTIONAL. Identifier for notification requests. Only present with credentials parameter.",
      ),

    transaction_id: z
      .string()
      .optional()
      .describe(
        "Conditional. Deferred issuance identifier; used in subsequent requests when credentials not immediately available. Present for deferred flow (HTTP 202).",
      ),
  })
  .strict()
  .superRefine((data, ctx) => {
    const hasCredentials = data.credentials !== undefined;
    const hasInterval = data.interval !== undefined;
    const hasTransactionId = data.transaction_id !== undefined;

    // Enforce XOR: credentials vs (interval + transaction_id)
    if (hasCredentials && (hasInterval || hasTransactionId)) {
      ctx.addIssue({
        code: "custom",
        message:
          "credentials MUST NOT be present with deferred flow fields (interval/transaction_id)",
        path: ["credentials"],
      });
    }

    // For deferred flow, require both interval and transaction_id
    if (!hasCredentials) {
      if (!hasInterval || !hasTransactionId) {
        ctx.addIssue({
          code: "custom",
          message:
            "Both interval and transaction_id are REQUIRED when credentials is not present (deferred flow)",
          path: hasInterval ? ["transaction_id"] : ["interval"],
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

export type CredentialResponseV1_3 = z.infer<typeof zCredentialResponseV1_3>;
