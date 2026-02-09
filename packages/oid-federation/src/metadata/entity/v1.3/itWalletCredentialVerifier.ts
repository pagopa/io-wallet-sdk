import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk";

/**
 * IT Wallet Credential Verifier Metadata for OpenID Federation v1.3.3
 *
 * This schema defines the metadata structure for OpenID credential verifiers
 * (relying parties) in the Italian Wallet ecosystem, aligned with specification v1.3.3.
 *
 * Key changes from v1.0:
 * - Added `logo_uri` field (MIME type MUST be application/svg)
 * - Added `encrypted_response_enc_values_supported` for content encryption algorithms
 * - Renamed `vp_formats` to `vp_formats_supported`
 * - Enhanced VP formats structure with separate algorithm arrays:
 *   - For SD-JWT: `sd-jwt_alg_values` and `kb-jwt_alg_values`
 *   - For mso_mdoc: `issuerauth_alg_values` and `deviceauth_alg_values` (COSE algorithm numbers)
 * - Removed deprecated JARM fields: `authorization_signed_response_alg`,
 *   `authorization_encrypted_response_alg`, `authorization_encrypted_response_enc`
 *
 * @see {@link https://italia.github.io/eidas-it-wallet-docs/versioned_docs/version-1.3.3/en/relying-party-metadata.html}
 */
export const itWalletCredentialVerifierMetadataV1_3 = z
  .object({
    application_type: z.literal("web"),
    client_id: z.string().url(),
    client_name: z.string(),
    encrypted_response_enc_values_supported: z.array(z.string()),
    erasure_endpoint: z.string().url().optional(),
    jwks: jsonWebKeySetSchema,
    logo_uri: z.string().url(),
    request_uris: z.array(z.string().url()),
    response_uris: z.array(z.string().url()),
    vp_formats_supported: z.record(
      z.string(),
      z.object({
        alg: z.array(z.string()).optional(),
        deviceauth_alg_values: z.array(z.number()).optional(),
        issuerauth_alg_values: z.array(z.number()).optional(),
        "kb-jwt_alg_values": z.array(z.string()).optional(),
        "sd-jwt_alg_values": z.array(z.string()).optional(),
      }),
    ),
  })
  .passthrough();

export type ItWalletCredentialVerifierMetadataV1_3 = z.input<
  typeof itWalletCredentialVerifierMetadataV1_3
>;

/**
 * Alias export for use in metadata unions
 * When importing from the v1.3 directory, this provides the v1.3 schema
 */
export const itWalletCredentialVerifierMetadata =
  itWalletCredentialVerifierMetadataV1_3;

export type ItWalletCredentialVerifierMetadata =
  ItWalletCredentialVerifierMetadataV1_3;

/**
 * Re-export the identifier from v1.0 as it remains unchanged
 */
export { itWalletCredentialVerifierIdentifier } from "../v1.0/itWalletCredentialVerifier";
