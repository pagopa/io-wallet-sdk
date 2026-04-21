import {
  ItWalletSpecsVersion,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

import { jsonWebKeySetSchema } from "../jwk/jwk";
import {
  ItWalletMetadataByVersion,
  isItWalletMetadataVersion,
  itWalletMetadataSchema,
  parseItWalletMetadataForVersion,
} from "../metadata/itWalletMetadata";
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

type BaseEntityStatementClaimsOptions = z.input<typeof baseSchema>;

type BaseEntityStatementClaims = z.output<typeof baseSchema>;

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
  BaseEntityStatementClaims,
  BaseEntityStatementClaimsOptions
> = entityStatementClaimsSchema;

export type ItWalletEntityStatementClaimsOptions = z.input<
  typeof itWalletEntityStatementClaimsSchema
>;

export type ItWalletEntityStatementClaims = z.output<
  typeof itWalletEntityStatementClaimsSchema
>;

type EntityStatementClaimsWithMetadata<TMetadata> = {
  metadata?: TMetadata;
} & Omit<ItWalletEntityStatementClaims, "metadata">;

export type ItWalletEntityStatementClaimsByVersion<
  V extends ItWalletSpecsVersion,
> = EntityStatementClaimsWithMetadata<ItWalletMetadataByVersion<V>>;

export function isItWalletEntityStatementClaimsVersion<
  V extends ItWalletSpecsVersion,
>(
  claims: unknown,
  version: V,
): claims is ItWalletEntityStatementClaimsByVersion<V> {
  const parsedClaims = itWalletEntityStatementClaimsSchema.safeParse(claims);

  if (!parsedClaims.success) {
    return false;
  }

  return (
    parsedClaims.data.metadata === undefined ||
    isItWalletMetadataVersion(parsedClaims.data.metadata, version)
  );
}

export function parseItWalletEntityStatementClaimsForVersion<
  V extends ItWalletSpecsVersion,
>(claims: unknown, version: V): ItWalletEntityStatementClaimsByVersion<V> {
  const parsedClaims = parseWithErrorHandling(
    itWalletEntityStatementClaimsSchema,
    claims,
    "invalid entity statement claims provided",
  );

  if (parsedClaims.metadata === undefined) {
    return parsedClaims as ItWalletEntityStatementClaimsByVersion<V>;
  }

  return {
    ...parsedClaims,
    metadata: parseItWalletMetadataForVersion(parsedClaims.metadata, version),
  } as ItWalletEntityStatementClaimsByVersion<V>;
}
