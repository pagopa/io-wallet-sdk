import { z } from "zod";

const zImageMetadata = z.looseObject({
  alt_text: z.string().optional(),
  uri: z.url(),
});

const zCredentialDisplayMetadata = z.looseObject({
  background_color: z.string().optional(),
  background_image: zImageMetadata.optional(),
  description: z.string().optional(),
  locale: z.string().optional(),
  logo: zImageMetadata.optional(),
  name: z.string(),
  text_color: z.string().optional(),
});

const zClaimsMetadata = z.looseObject({
  display: z
    .array(
      z.looseObject({
        locale: z.string().optional(),
        name: z.string().optional(),
      }),
    )
    .optional(),
  mandatory: z.boolean().optional(),
  path: z.array(z.union([z.string(), z.number(), z.null()])),
});

const zCredentialMetadata = z.looseObject({
  claims: z.array(zClaimsMetadata).optional(),
  display: z.array(zCredentialDisplayMetadata).optional(),
});

const zKeyAttestationsRequired = z.looseObject({
  key_storage: z.array(z.string()).optional(),
  user_authentication: z.array(z.string()).optional(),
});

const zProofType = z.looseObject({
  key_attestations_required: zKeyAttestationsRequired.optional(),
  proof_signing_alg_values_supported: z.array(z.string()).min(1),
});

const zProofTypesSupported = z
  .looseObject({
    attestation: zProofType.optional(),
    jwt: zProofType.optional(),
  })
  .refine((proofTypes) => proofTypes.jwt || proofTypes.attestation, {
    message:
      "The proof_types_supported object MUST include 'jwt' or 'attestation'.",
  });

const zCredentialConfigurationBase = z.looseObject({
  credential_metadata: zCredentialMetadata.optional(),
  cryptographic_binding_methods_supported: z.array(z.string()).optional(),
  proof_types_supported: zProofTypesSupported.optional(),
  scope: z.string().optional(),
});

const zSdJwtVcCredentialConfiguration = zCredentialConfigurationBase.extend({
  credential_signing_alg_values_supported: z.array(z.string()).optional(),
  format: z.literal("dc+sd-jwt"),
  vct: z.string(),
});

const zMdocCredentialConfiguration = zCredentialConfigurationBase.extend({
  credential_signing_alg_values_supported: z.array(z.number().int()).optional(),
  doctype: z.string(),
  format: z.literal("mso_mdoc"),
});

const zCredentialConfiguration = z.discriminatedUnion("format", [
  zSdJwtVcCredentialConfiguration,
  zMdocCredentialConfiguration,
]);

const zIssuerInfo = z.looseObject({
  data: z.union([z.string(), z.record(z.string(), z.unknown())]),
  format: z.string(),
});

/**
 *
 * {@link https://aptitude-consortium.github.io/aptitude-eudi-wallet-specs/latest/RFCs/RFC001/#89-metadata-endpoints}
 *
 */
export const aptitudeCredentialIssuerMetadata = z.looseObject({
  authorization_servers: z.tuple([z.url()], z.url()).optional(),
  batch_credential_issuance: z
    .looseObject({ batch_size: z.number().int().positive() })
    .optional(),
  credential_configurations_supported: z.record(
    z.string(),
    zCredentialConfiguration,
  ),
  credential_endpoint: z.url(),
  credential_issuer: z.url(),
  deferred_credential_endpoint: z.url().optional(),
  display: z
    .array(
      z.looseObject({
        locale: z.string().optional(),
        logo: zImageMetadata.optional(),
        name: z.string().optional(),
      }),
    )
    .optional(),
  issuer_info: z.array(zIssuerInfo).min(1),
  nonce_endpoint: z.url(),
  notification_endpoint: z.url().optional(),
});

export type AptitudeCredentialIssuerMetadata = z.input<
  typeof aptitudeCredentialIssuerMetadata
>;

export const aptitudeCredentialIssuerIdentifier = "openid_credential_issuer";
