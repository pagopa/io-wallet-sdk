import { z } from "zod";

import { zBaseCredentialResponse } from "../z-base-credential-response";

/**
 * Credential Response schema for IT Wallet v1.0.2
 *
 * Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.0.2/en/credential-issuer-endpoint.html#credential-response
 *
 * Response contains either:
 * - Immediate issuance (HTTP 200): `credentials` (array)
 * - Deferred issuance (HTTP 202): `lead_time` + `transaction_id`
 */
export const zCredentialResponseV1_0 = zBaseCredentialResponse
  .extend({
    lead_time: z
      .number()
      .int()
      .positive()
      .optional()
      .describe(
        "REQUIRED if credentials is not present, otherwise it MUST NOT be present. The amount of time (in seconds) required before making a Deferred Credential Request.",
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
