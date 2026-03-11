import { z } from "zod";

import { zImmediateCredentialResponse } from "../z-immediate-credential-response";

export const zDeferredCredentialResponseV1_0 = z.strictObject({
  lead_time: z
    .number()
    .int()
    .positive()
    .describe(
      "REQUIRED if credentials is not present, otherwise it MUST NOT be present. The amount of time (in seconds) required before making a Deferred Credential Request.",
    ),
  transaction_id: z.string().nonempty(),
});

export type DeferredCredentialResponseV1_0 = z.infer<
  typeof zDeferredCredentialResponseV1_0
>;

export const zCredentialResponseV1_0 = z.union([
  zImmediateCredentialResponse,
  zDeferredCredentialResponseV1_0,
]);

export type CredentialResponseV1_0 = z.infer<typeof zCredentialResponseV1_0>;
