import { z } from "zod";

import type { CredentialRequestV1_0 } from "./v1.0";
import type { CredentialRequestV1_3 } from "./v1.3";

/**
 * Base Credential request schema for IT-Wallet v1.0 and v1.3.
 * @internal
 */
export const zBaseCredentialRequest = z.object({
  credential_configuration_id: z
    .string()
    .optional()
    .describe(
      "REQUIRED if credential_identifier param is absent. MUST NOT be used otherwise.",
    ),

  credential_identifier: z
    .string()
    .optional()
    .describe(
      "REQUIRED when Authorization Details of type openid_credential was returned. MUST NOT be used if credential_configuration_id is present.",
    ),

  transaction_id: z
    .string()
    .optional()
    .describe(
      "REQUIRED only in case of deferred flow. MUST NOT be present in immediate flow.",
    ),
});

export function credentialRequestRefiner(
  data: CredentialRequestV1_0 | CredentialRequestV1_3,
  ctx: z.RefinementCtx,
) {
  // Exclusive OR between credential_identifier and credential_configuration_id
  if (data.credential_identifier && data.credential_configuration_id) {
    ctx.addIssue({
      code: "custom",
      message:
        "credential_identifier and credential_configuration_id MUST NOT be used together",
      path: ["credential_identifier"],
    });
  }

  if (!data.credential_identifier && !data.credential_configuration_id) {
    ctx.addIssue({
      code: "custom",
      message:
        "One of credential_identifier or credential_configuration_id MUST be present",
      path: ["credential_identifier"],
    });
  }
}
