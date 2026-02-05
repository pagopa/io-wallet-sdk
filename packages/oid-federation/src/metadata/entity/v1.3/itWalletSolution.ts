import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk";

const walletMetadataSchema = z
  .object({
    authorization_endpoint: z.string().url(),
    client_id_prefixes_supported: z.array(
      z.enum(["openid_federation", "x509_hash"]),
    ),
    credential_offer_endpoint: z.string().url(),
    request_object_signing_alg_values_supported: z.array(z.string()),
    response_modes_supported: z.array(z.literal("query")).min(1),
    response_types_supported: z.array(z.string()),
    vp_formats_supported: z.record(z.string(), z.object({}).passthrough()),
    wallet_name: z.string(),
  })
  .passthrough();

export const itWalletSolutionEntityMetadata = z
  .object({
    jwks: jsonWebKeySetSchema.optional(),
    jwks_uri: z.string().url().optional(),
    // logo_uri MIME type MUST be application/svg per spec; validated at fetch-time
    logo_uri: z.string().url(),
    signed_jwks_uri: z.string().url().optional(),
    wallet_metadata: walletMetadataSchema,
  })
  .passthrough();

export type ItWalletSolutionEntityMetadata = z.input<
  typeof itWalletSolutionEntityMetadata
>;

export const itWalletSolutionEntityIdentifier = "wallet_solution";
