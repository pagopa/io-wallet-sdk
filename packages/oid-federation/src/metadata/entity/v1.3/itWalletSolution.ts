import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk/jwk";

const walletMetadataSchema = z.looseObject({
  authorization_endpoint: z.url(),
  client_id_prefixes_supported: z.array(
    z.enum(["openid_federation", "x509_hash"]),
  ),
  credential_offer_endpoint: z.url(),
  request_object_signing_alg_values_supported: z.array(z.string()),
  response_modes_supported: z.array(z.literal("query")).min(1),
  response_types_supported: z.array(z.string()),
  vp_formats_supported: z.record(z.string(), z.looseObject({})),
  wallet_name: z.string(),
});

export const itWalletSolutionEntityMetadata = z.looseObject({
  jwks: jsonWebKeySetSchema.optional(),
  jwks_uri: z.url().optional(),
  // logo_uri MIME type MUST be application/svg per spec; validated at fetch-time
  logo_uri: z.url(),
  signed_jwks_uri: z.url().optional(),
  wallet_metadata: walletMetadataSchema,
});

export type ItWalletSolutionEntityMetadata = z.input<
  typeof itWalletSolutionEntityMetadata
>;

export const itWalletSolutionEntityIdentifier = "wallet_solution";
