import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk";

/**
 * Image metadata with integrity hash support
 * Follows IT Wallet v1.3 specification
 */
type ImageMetadata = z.infer<typeof ImageMetadata>;
const ImageMetadata = z.object({
  alt_text: z.string().optional(),
  uri: z.string().url(),
  "uri#integrity": z.string().optional(),
});

/**
 * Enhanced credential display metadata
 * Supports background images, watermarks, and colors
 */
type CredentialDisplayMetadata = z.infer<typeof CredentialDisplayMetadata>;
const CredentialDisplayMetadata = z.object({
  background_color: z.string().optional(),
  background_image: ImageMetadata.optional(),
  description: z.string().optional(),
  locale: z.string(),
  logo: ImageMetadata.optional(),
  name: z.string(),
  watermark_image: ImageMetadata.optional(),
});

/**
 * Claim display metadata
 */
type ClaimDisplayMetadata = z.infer<typeof ClaimDisplayMetadata>;
const ClaimDisplayMetadata = z.object({
  description: z.string().optional(),
  locale: z.string(),
  name: z.string(),
});

/**
 * Enhanced claims metadata with selective disclosure and mandatory flags
 */
type ClaimsMetadata = z.infer<typeof ClaimsMetadata>;
const ClaimsMetadata = z.object({
  display: z.array(ClaimDisplayMetadata).optional(),
  mandatory: z.boolean().optional(),
  path: z.array(z.union([z.string(), z.number(), z.null()])),
  sd: z.enum(["always", "never"]).optional(),
});

/**
 * Complete credential metadata structure
 * This is the new mandatory field in credential_configurations_supported
 */
type CredentialMetadata = z.infer<typeof CredentialMetadata>;
const CredentialMetadata = z.object({
  claims: z.array(ClaimsMetadata).optional(),
  display: z.array(CredentialDisplayMetadata).optional(),
});

/**
 * Enhanced proof types support with optional key attestations
 * References OpenID4VCI Appendix F.1 and Section 12.2
 */
type ProofTypesSupported = z.infer<typeof ProofTypesSupported>;
const ProofTypesSupported = z.object({
  jwt: z.object({
    key_attestations_required: z.boolean().optional(),
    proof_signing_alg_values_supported: z.array(z.string()),
  }),
});

/**
 * Authentic sources metadata linking to trusted data sources
 */
type AuthenticSources = z.infer<typeof AuthenticSources>;
const AuthenticSources = z.object({
  dataset_id: z.string(),
  entity_id: z.string(),
});

/**
 * Enhanced metadata for a credential supported by an Issuer
 * Includes new mandatory credential_metadata, schema_id, and authentic_sources
 */
type SupportedCredentialMetadata = z.infer<typeof SupportedCredentialMetadata>;
const SupportedCredentialMetadata = z.intersection(
  z.discriminatedUnion("format", [
    z.object({ format: z.literal("dc+sd-jwt"), vct: z.string() }),
    z.object({ doctype: z.string(), format: z.literal("mso_mdoc") }),
  ]),
  z.object({
    authentic_sources: AuthenticSources,
    credential_metadata: CredentialMetadata,
    credential_signing_alg_values_supported: z.array(z.string()),
    cryptographic_binding_methods_supported: z.array(z.string()),
    proof_types_supported: ProofTypesSupported,
    schema_id: z.string(),
    scope: z.string(),
  }),
);

/**
 * IT Wallet Credential Issuer Metadata for v1.3 specification
 *
 * Changes from v1.0:
 * - REMOVED: revocation_endpoint, status_assertion_endpoint, credential_hash_alg_supported, evidence_supported
 * - ADDED: batch_credential_issuance, status_list_aggregation_endpoint
 * - MODIFIED: credential_configurations_supported now requires credential_metadata, schema_id, authentic_sources
 * - MODIFIED: proof_types_supported supports key_attestations_required
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.3.0/en/credential-issuer-solution.html#metadata-for-openid-credential-issuer}
 */
export const itWalletCredentialIssuerMetadata = z
  .object({
    authorization_servers: z.array(z.string().url()).optional(),
    batch_credential_issuance: z
      .object({
        batch_size: z.number().int().positive(),
      })
      .optional(),
    credential_configurations_supported: z.record(SupportedCredentialMetadata),
    credential_endpoint: z.string().url(),
    credential_issuer: z.string().url(),
    deferred_credential_endpoint: z.string().url().optional(),
    display: z.array(CredentialDisplayMetadata).optional(),
    jwks: jsonWebKeySetSchema,
    nonce_endpoint: z.string().url().optional(),
    notification_endpoint: z.string().url().optional(),
    status_attestation_endpoint: z.string().url().optional(),
    status_list_aggregation_endpoint: z.string().url().optional(),
    trust_frameworks_supported: z.array(
      z.union([
        z.literal("eudi_wallet"),
        z.literal("it_cie"),
        z.literal("it_wallet"),
        z.literal("it_l2+document_proof"),
      ]),
    ),
  })
  .passthrough();

export type ItWalletCredentialIssuerMetadata = z.input<
  typeof itWalletCredentialIssuerMetadata
>;

export const itWalletCredentialIssuerIdentifier = "openid_credential_issuer";
