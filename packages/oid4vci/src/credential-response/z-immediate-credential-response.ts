import { z } from "zod";

export const zCredentialObjectSchema = z.object({
  credential: z.string(),
});

export type CredentialObject = z.infer<typeof zCredentialObjectSchema>;

export const zImmediateCredentialResponse = z
  .object({
    credentials: z
      .array(zCredentialObjectSchema)
      .nonempty()
      .describe(
        "Conditional. Array of issued Digital Credentials as JSON objects with `credential` member containing encoded credential string. Present for immediate issuance (HTTP 200).",
      ),
    notification_id: z
      .string()
      .optional()
      .describe(
        "OPTIONAL. Identifier for notification requests. Only present with credentials parameter.",
      ),
  })
  .strict();

export type ImmediateCredentialResponse = z.infer<
  typeof zImmediateCredentialResponse
>;
