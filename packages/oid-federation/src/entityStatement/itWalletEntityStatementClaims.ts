import { z } from "zod";

import { jsonWebKeySetSchema } from "../jwk/jwk";
import { itWalletMetadataSchema } from "../metadata/itWalletMetadata";
import { metadataPolicySchema } from "../metadata/policy";
import { constraintSchema } from "./z-constraint";
import {
  trustMarkIssuerSchema,
  trustMarkOwnerSchema,
  trustMarkSchema,
} from "./z-trustmark";

const baseSchema = z.object({
  authority_hints: z.array(z.url()).optional(),
  constraints: constraintSchema.optional(),
  crit: z.array(z.string()).optional(),
  exp: z
    .number()
    .describe("Expiration time as a UNIX timestamp in seconds since epoch"),
  iat: z
    .number()
    .describe("Issued-at time as a UNIX timestamp in seconds since epoch"),
  iss: z.string(),
  jwks: jsonWebKeySetSchema,
  metadata: itWalletMetadataSchema.optional(),
  metadata_policy: z
    .record(z.string(), z.record(z.string(), metadataPolicySchema).optional())
    .optional(),
  metadata_policy_crit: z.array(z.string()).optional(),
  source_endpoint: z.url().optional(),
  sub: z.string(),
  trust_mark_issuers: trustMarkIssuerSchema.optional(),
  trust_mark_owners: trustMarkOwnerSchema.optional(),
  trust_marks: z.array(trustMarkSchema).optional(),
});

type ItWalletEntityStatementClaimsOptions = z.input<typeof baseSchema>;

type ItWalletEntityStatementClaims = z.output<typeof baseSchema>;

const entityStatementClaimsSchema = baseSchema.loose().refine(
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

// The explicit type annotation here is necessary to avoid this node exceeds the maximum length the compiler will serialize.
export const itWalletEntityStatementClaimsSchema: z.ZodType<
  ItWalletEntityStatementClaims,
  ItWalletEntityStatementClaimsOptions
> = entityStatementClaimsSchema;
