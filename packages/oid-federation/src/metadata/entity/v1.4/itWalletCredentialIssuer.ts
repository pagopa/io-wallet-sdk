import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk/jwk";

export type ImageMetadata = z.infer<typeof ImageMetadata>;
export const ImageMetadata = z.object({
  alt_text: z.string().optional(),
  uri: z.url(),
  "uri#integrity": z.string().optional(),
});

export type CredentialDisplayMetadata = z.infer<
  typeof CredentialDisplayMetadata
>;

export const CredentialDisplayMetadata = z.object({
  background_color: z.string().optional(),
  background_image: ImageMetadata.optional(),
  description: z.string().optional(),
  label: z.string(),
  locale: z.string(),
  logo: ImageMetadata.optional(),
  watermark_image: ImageMetadata.optional(),
});

export type ClaimDisplayMetadata = z.infer<typeof ClaimDisplayMetadata>;
export const ClaimDisplayMetadata = z.object({
  description: z.string().optional(),
  locale: z.string(),
  name: z.string(),
});

export type ClaimsMetadata = z.infer<typeof ClaimsMetadata>;
export const ClaimsMetadata = z.object({
  display: z.array(ClaimDisplayMetadata).optional(),
  mandatory: z.boolean().optional(),
  path: z.array(z.union([z.string(), z.number(), z.null()])),
  sd: z.enum(["always", "never"]).optional(),
});

export type CredentialMetadata = z.infer<typeof CredentialMetadata>;
export const CredentialMetadata = z.object({
  claims: z.array(ClaimsMetadata).optional(),
  display: z.array(CredentialDisplayMetadata).optional(),
});

export const zKeyStorageLevel = z.enum([
  "iso_18045_high",
  "iso_18045_moderate",
  "iso_18045_enhanced-basic",
  "iso_18045_basic",
]);

export type KeyStorageLevel = z.infer<typeof zKeyStorageLevel>;

export const zUserAuthenticationLevel = zKeyStorageLevel;
export type UserAuthenticationLevel = KeyStorageLevel;

export type ProofTypesSupported = z.infer<typeof ProofTypesSupported>;
export const ProofTypesSupported = z.object({
  jwt: z.object({
    key_attestations_required: z
      .object({
        key_storage: z.array(zKeyStorageLevel).min(1).optional(),
        user_authentication: z
          .array(zUserAuthenticationLevel)
          .min(1)
          .optional(),
      })
      .optional(),
    proof_signing_alg_values_supported: z.array(z.string()),
  }),
});

export type AuthenticSources = z.infer<typeof AuthenticSources>;
export const AuthenticSources = z.object({
  dataset_id: z.string(),
  entity_id: z.string(),
});

export type SupportedCredentialMetadata = z.infer<
  typeof SupportedCredentialMetadata
>;

export const SupportedCredentialMetadata = z.intersection(
  z.discriminatedUnion("format", [
    z.object({
      credential_signing_alg_values_supported: z.array(z.string()),
      format: z.literal("dc+sd-jwt"),
      vct: z.string(),
    }),
    z.object({
      credential_signing_alg_values_supported: z.array(z.number().int()),
      doctype: z.string(),
      format: z.literal("mso_mdoc"),
    }),
  ]),
  z.object({
    authentic_sources: AuthenticSources,
    credential_metadata: CredentialMetadata,
    cryptographic_binding_methods_supported: z.array(z.string()),
    proof_types_supported: ProofTypesSupported,
    schema_id: z.string(),
    scope: z.string(),
  }),
);

/**
 * IT Wallet Credential Issuer Metadata for v1.4 specification
 *
 * Changes from v1.3:
 * - MODIFIED: CredentialDisplayMetadata uses `label` instead of `name` (IETF draft-ietf-oauth-sd-jwt-vc-12 §claim-display-metadata)
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.4.0/en/credential-issuer-solution.html#metadata-for-openid-credential-issuer}
 */
export const itWalletCredentialIssuerMetadata = z.looseObject({
  authorization_servers: z.tuple([z.url()], z.url()).optional(),
  batch_credential_issuance: z
    .object({
      batch_size: z.number().int().positive(),
    })
    .optional(),
  credential_configurations_supported: z.record(
    z.string(),
    SupportedCredentialMetadata,
  ),
  credential_endpoint: z.url(),
  credential_issuer: z.url(),
  deferred_credential_endpoint: z.url().optional(),
  display: z.array(CredentialDisplayMetadata).optional(),
  jwks: jsonWebKeySetSchema,
  nonce_endpoint: z.url().optional(),
  notification_endpoint: z.url().optional(),
  status_list_aggregation_endpoint: z.url().optional(),
  trust_frameworks_supported: z.array(
    z.union([
      z.literal("eudi_wallet"),
      z.literal("it_cie"),
      z.literal("it_wallet"),
      z.literal("it_l2+document_proof"),
      /** @deprecated For backward compatibility only, will be removed in future versions. */
      z.literal("it_spid"),
    ]),
  ),
});

export type ItWalletCredentialIssuerMetadata = z.input<
  typeof itWalletCredentialIssuerMetadata
>;

export const itWalletCredentialIssuerIdentifier = "openid_credential_issuer";
