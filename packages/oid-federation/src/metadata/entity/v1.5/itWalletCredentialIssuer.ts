import { z } from "zod";

import { itWalletCredentialIssuerMetadata as itWalletCredentialIssuerMetadataV1_3 } from "../v1.3/itWalletCredentialIssuer";

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
 * IT Wallet Credential Issuer Metadata for v1.5 specification
 *
 * Changes from v1.3:
 * - ADDED: issuer_info
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.5.0/en/credential-issuer-metadata.html#metadata-for-openid-credential-issuer}
 */
export const itWalletCredentialIssuerMetadata =
  itWalletCredentialIssuerMetadataV1_3.extend({
    issuer_info: z.array(IssuerInfo).nonempty().optional(),
  });

export type ItWalletCredentialIssuerMetadata = z.input<
  typeof itWalletCredentialIssuerMetadata
>;

export const itWalletCredentialIssuerIdentifier = "openid_credential_issuer";
