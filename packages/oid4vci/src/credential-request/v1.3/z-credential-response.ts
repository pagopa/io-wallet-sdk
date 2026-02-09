import { z } from "zod";

import { zBaseCredentialResponse } from "../z-base-credential-response";

/**
 * Credential Response schema for IT Wallet v1.3.3
 *
 * Reference: https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/credential-issuer-endpoint.html#credential-response
 *
 * Response contains either:
 * - Immediate issuance (HTTP 200): `credentials` (array)
 * - Deferred issuance (HTTP 202): `interval` + `transaction_id`
 */
export const zCredentialResponseV1_3 = zBaseCredentialResponse
  .extend({
    interval: z
      .number()
      .int()
      .positive()
      .optional()
      .describe(
        "REQUIRED if transaction_id is present, otherwise it MUST NOT be present. The amount of time (in seconds) required before making a Deferred Credential Request",
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
