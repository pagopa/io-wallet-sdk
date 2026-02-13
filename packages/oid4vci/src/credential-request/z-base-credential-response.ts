import { z } from "zod";

const zCredentialObjectSchema = z.object({
  credential: z.string(),
});

export const zBaseCredentialResponse = z.object({
  credentials: z
    .array(zCredentialObjectSchema)
    .nonempty()
    .optional()
    .describe(
      "Conditional. Array of issued Digital Credentials as JSON objects with `credential` member containing encoded credential string. Present for immediate issuance (HTTP 200).",
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
});
