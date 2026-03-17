import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk";

/**
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.1.0/en/credential-issuer-solution.html#metadata-for-openid-credential-issuer}
 *
 */
export type CredentialDisplayMetadata = z.infer<
  typeof CredentialDisplayMetadata
>;
export const CredentialDisplayMetadata = z.object({
  locale: z.string(),
  name: z.string(),
});

export type ClaimsMetadata = z.infer<typeof ClaimsMetadata>;
export const ClaimsMetadata = z.object({
  display: z.array(CredentialDisplayMetadata),
  path: z.array(z.union([z.string(), z.number(), z.null()])),
});

// Metadata for a credential which is supported by an Issuer
export type SupportedCredentialMetadata = z.infer<
  typeof SupportedCredentialMetadata
>;

export const SupportedCredentialMetadata = z.intersection(
  z.discriminatedUnion("format", [
    z.object({ format: z.literal("dc+sd-jwt"), vct: z.string() }),
    z.object({ doctype: z.string(), format: z.literal("mso_mdoc") }),
  ]),
  z.object({
    claims: z.array(ClaimsMetadata),
    credential_signing_alg_values_supported: z.array(z.string()),
    cryptographic_binding_methods_supported: z.array(z.string()),
    display: z.array(CredentialDisplayMetadata),
    proof_types_supported: z.object({
      jwt: z.object({
        proof_signing_alg_values_supported: z.array(z.string()),
      }),
    }),
    scope: z.string(),
  }),
);

export const itWalletCredentialIssuerMetadata = z.looseObject({
  authorization_servers: z.array(z.url()).optional(),
  batch_credential_issuance: z.object({
    batch_size: z.number().int(),
  }),
  credential_configurations_supported: z.record(
    z.string(),
    SupportedCredentialMetadata,
  ),
  credential_endpoint: z.url(),
  credential_hash_alg_supported: z.string(),
  credential_issuer: z.url(),
  deferred_credential_endpoint: z.url(),
  display: z.array(CredentialDisplayMetadata),
  evidence_supported: z
    .array(z.string())
    .refine((arr) => arr.includes("vouch"), {
      message: "The evidence_supported array MUST include 'vouch'.",
    }),
  jwks: jsonWebKeySetSchema,
  nonce_endpoint: z.url(),
  notification_endpoint: z.url(),
  revocation_endpoint: z.url(),
  status_assertion_endpoint: z.url(),
  status_attestation_endpoint: z.url(),
  trust_frameworks_supported: z.array(
    z.union([
      z.literal("it_cie"),
      z.literal("it_wallet"),
      z.literal("eudi_wallet"),
    ]),
  ),
});

export type ItWalletCredentialIssuerMetadata = z.input<
  typeof itWalletCredentialIssuerMetadata
>;

export const itWalletCredentialIssuerIdentifier = "openid_credential_issuer";
