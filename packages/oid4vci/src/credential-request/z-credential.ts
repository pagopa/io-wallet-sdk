import type { ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";

import { z } from "zod";

import {
  type CredentialRequestV1_0_2,
  zCredentialRequestV1_0_2,
} from "./v1.0.2";
import {
  type CredentialRequestV1_3_3,
  zCredentialRequestV1_3_3,
} from "./v1.3.3";

/**
 * Schema registry mapping versions to their credential request schemas
 */
export interface CredentialRequestSchemaRegistry {
  "1.0.2": typeof zCredentialRequestV1_0_2;
  "1.3.3": typeof zCredentialRequestV1_3_3;
}

/**
 * Conditional type: Get the credential request type for a specific version
 */
export type CredentialRequestForVersion<V extends ItWalletSpecsVersion> =
  V extends "1.0.2"
    ? CredentialRequestV1_0_2
    : V extends "1.3.3"
      ? CredentialRequestV1_3_3
      : never;

/**
 * Get the appropriate credential request schema for a version
 *
 * @param version - IT Wallet specification version
 * @returns Zod schema for the specified version
 */
export function getCredentialRequestSchema<V extends ItWalletSpecsVersion>(
  version: V,
): CredentialRequestSchemaRegistry[V] {
  const schemas: CredentialRequestSchemaRegistry = {
    "1.0.2": zCredentialRequestV1_0_2,
    "1.3.3": zCredentialRequestV1_3_3,
  };
  return schemas[version];
}

/**
 * Credential Response schema (version-agnostic)
 * The response format is the same across v1.0.2 and v1.3.3
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
