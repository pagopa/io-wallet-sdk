import { z } from "zod";

import { zFederationJwkSet } from "../../../jwk/z-federation-jwk";

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
  key_storage: z.array(z.string()).min(1).optional(),
  user_authentication: z.array(z.string()).min(1).optional(),
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
  cryptographic_binding_methods_supported: z
    .array(z.string())
    .min(1)
    .optional(),
  proof_types_supported: zProofTypesSupported.optional(),
  scope: z.string().optional(),
});

const zSdJwtVcCredentialConfiguration = zCredentialConfigurationBase.extend({
  credential_signing_alg_values_supported: z
    .array(z.string())
    .min(1)
    .optional(),
  format: z.literal("dc+sd-jwt"),
  vct: z.string(),
});

const zLegacySdJwtVcCredentialConfiguration =
  zSdJwtVcCredentialConfiguration.extend({
    format: z.literal("vc+sd-jwt"),
  });

const zMdocCredentialConfiguration = zCredentialConfigurationBase.extend({
  credential_signing_alg_values_supported: z
    .array(z.number().int())
    .min(1)
    .optional(),
  doctype: z.string(),
  format: z.literal("mso_mdoc"),
});

const zLegacyCredentialConfiguration = z.discriminatedUnion("format", [
  zSdJwtVcCredentialConfiguration,
  zLegacySdJwtVcCredentialConfiguration,
  zMdocCredentialConfiguration,
]);

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const zCredentialConfiguration = z.discriminatedUnion("format", [
  zSdJwtVcCredentialConfiguration,
  zMdocCredentialConfiguration,
]);
type CredentialConfiguration = z.output<typeof zCredentialConfiguration>;

/**
 * Compatibility parser for OID4VCI `credential_configuration_supported`
 * which allows configurations where the legacy SD-JWT-VC identifier
 * `vc+sd-jwt` is used, but it just filters them out from the final result.
 * Necessary for interoperability with issuers that post configurations for
 * credentials that cannot be updated.
 */
const zCredentialConfigurationsSupported = z
  .record(z.string(), zLegacyCredentialConfiguration)
  .transform((configs) =>
    Object.fromEntries(
      Object.entries(configs).filter(
        (entry): entry is [string, CredentialConfiguration] =>
          entry[1].format !== "vc+sd-jwt",
      ),
    ),
  );

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
    .looseObject({ batch_size: z.number().int().min(2) })
    .optional(),
  credential_configurations_supported: zCredentialConfigurationsSupported,
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
  // TODO [WLS-188] : This field should become mandatory when the various WRP will consistently use Register Metadata and WRPRC.
  issuer_info: z.array(zIssuerInfo).min(1).optional(),
  // TODO [WLS-185] : This option has been added only for temporary compatibility with ITW
  // When the APTITUDE trust model will be effectively implemented and signing keys will
  // be retrieved and verified via the LoTE + x5c mechanism this can be removed
  jwks: zFederationJwkSet.optional(),
  nonce_endpoint: z.url(),
  notification_endpoint: z.url().optional(),
});

export type AptitudeCredentialIssuerMetadata = z.input<
  typeof aptitudeCredentialIssuerMetadata
>;

export const aptitudeCredentialIssuerIdentifier = "openid_credential_issuer";
