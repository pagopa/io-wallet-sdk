import { z } from "zod";

import { zImmediateCredentialResponse } from "../z-immediate-credential-response";

export const zDeferredCredentialResponseV1_3 = z
  .object({
    interval: z
      .number()
      .int()
      .positive()
      .describe(
        "REQUIRED if transaction_id is present, otherwise it MUST NOT be present. The amount of time (in seconds) required before making a Deferred Credential Request",
      ),
    transaction_id: z.string().nonempty(),
  })
  .strict();

export type DeferredCredentialResponseV1_3 = z.infer<
  typeof zDeferredCredentialResponseV1_3
>;

export const zCredentialResponseV1_3 = z.union([
  zImmediateCredentialResponse,
  zDeferredCredentialResponseV1_3,
]);

export type CredentialResponseV1_3 = z.infer<typeof zCredentialResponseV1_3>;
