import {
  constraintSchema,
  metadataPolicySchema,
  trustMarkIssuerSchema,
  trustMarkOwnerSchema,
  trustMarkSchema,
} from "@openid-federation/core";
import { z } from "zod";

import { jsonWebKeySetSchema } from "../jwk/jwk";
import { itWalletMetadataSchema } from "../metadata/itWalletMetadata";

const baseSchema = z.object({
  authority_hints: z.array(z.string().url()).optional(),
  constraints: constraintSchema.optional(),
  crit: z.array(z.string()).optional(),
  exp: z.number(),
  iat: z.number(),
  iss: z.string(),
  jwks: jsonWebKeySetSchema,
  metadata: itWalletMetadataSchema.optional(),
  metadata_policy: z
    .record(z.record(metadataPolicySchema).optional())
    .optional(),
  metadata_policy_crit: z.array(z.string()).optional(),
  source_endpoint: z.string().url().optional(),
  sub: z.string(),
  trust_mark_issuers: trustMarkIssuerSchema.optional(),
  trust_mark_owners: trustMarkOwnerSchema.optional(),
  trust_marks: z.array(trustMarkSchema).optional(),
});

export type ItWalletEntityStatementClaimsOptions = z.input<typeof baseSchema>;

export type ItWalletEntityStatementClaims = z.output<typeof baseSchema>;

export const itWalletEntityStatementClaimsSchema: z.ZodType<
  ItWalletEntityStatementClaims,
  z.ZodTypeDef,
  ItWalletEntityStatementClaimsOptions
> = baseSchema.passthrough().refine(
  (data) => {
    const keyIds = data.jwks.keys.map((key) => key.kid);
    const uniqueKeyIds = new Set(keyIds);
    return uniqueKeyIds.size === keyIds.length;
  },
  {
    message: "keys include duplicate key ids",
    path: ["jwks", "keys"],
  },
);
