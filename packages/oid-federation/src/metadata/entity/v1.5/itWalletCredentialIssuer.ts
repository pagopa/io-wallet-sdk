import { z } from "zod";

import {
  AuthenticSources,
  SupportedCredentialCommonMetadata as SupportedCredentialCommonMetadataV1_3,
  SupportedCredentialFormatMetadata,
  itWalletCredentialIssuerMetadata as itWalletCredentialIssuerMetadataV1_3,
} from "../v1.3/itWalletCredentialIssuer";

export type IssuerInfo = z.infer<typeof IssuerInfo>;
export const IssuerInfo = z.discriminatedUnion("format", [
  z.object({
    data: z.string(),
    format: z.literal("registration_cert"),
  }),
  z.object({
    data: z.looseObject({}),
    format: z.literal("registrar_dataset"),
  }),
]);

/**
 * Credential configuration for v1.5: `authentic_sources` is required only when
 * `parent_credentials` is absent, and vice versa.
 */
export type SupportedCredentialMetadata = z.infer<
  typeof SupportedCredentialMetadata
>;
export const SupportedCredentialMetadata = z
  .intersection(
    SupportedCredentialFormatMetadata,
    SupportedCredentialCommonMetadataV1_3.extend({
      authentic_sources: AuthenticSources.optional(),
      parent_credentials: z.array(z.string()).nonempty().optional(),
    }),
  )
  .refine(
    (config) =>
      config.authentic_sources !== undefined ||
      config.parent_credentials !== undefined,
    {
      message:
        "Either authentic_sources or parent_credentials must be provided",
    },
  );

/**
 * IT Wallet Credential Issuer Metadata for v1.5 specification
 *
 * Changes from v1.3:
 * - ADDED: issuer_info
 * - MODIFIED: credential configurations accept parent_credentials as an alternative to authentic_sources
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.5.0/en/credential-issuer-metadata.html#metadata-for-openid-credential-issuer}
 */
export const itWalletCredentialIssuerMetadata =
  itWalletCredentialIssuerMetadataV1_3.extend({
    credential_configurations_supported: z.record(
      z.string(),
      SupportedCredentialMetadata,
    ),
    issuer_info: z.array(IssuerInfo).nonempty().optional(),
  });

export type ItWalletCredentialIssuerMetadata = z.input<
  typeof itWalletCredentialIssuerMetadata
>;

export const itWalletCredentialIssuerIdentifier = "openid_credential_issuer";
