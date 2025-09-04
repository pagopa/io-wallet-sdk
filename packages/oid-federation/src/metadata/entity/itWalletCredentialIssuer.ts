import { z } from "zod";
import { JWKS } from "../../jwk";

/**
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.1.0/en/credential-issuer-solution.html#metadata-for-openid-credential-issuer}
 *
 */
type CredentialDisplayMetadata = z.infer<typeof CredentialDisplayMetadata>;
const CredentialDisplayMetadata = z.object({
  name: z.string(),
  locale: z.string(),
});

type ClaimsMetadata = z.infer<typeof ClaimsMetadata>;
const ClaimsMetadata = z.object({
  path: z.array(z.union([z.string(), z.number(), z.null()])),
  display: z.array(CredentialDisplayMetadata),
});

// Metadata for a credential which is supported by an Issuer
type SupportedCredentialMetadata = z.infer<typeof SupportedCredentialMetadata>;
const SupportedCredentialMetadata = z.intersection(
  z.discriminatedUnion("format", [
    z.object({ format: z.literal("dc+sd-jwt"), vct: z.string() }),
    z.object({ format: z.literal("mso_mdoc"), doctype: z.string() }),
  ]),
  z.object({
    scope: z.string(),
    display: z.array(CredentialDisplayMetadata),
    claims: z.array(ClaimsMetadata),
    cryptographic_binding_methods_supported: z.array(z.string()),
    credential_signing_alg_values_supported: z.array(z.string()),
    proof_types_supported: z.object({
      jwt: z.object({
        proof_signing_alg_values_supported: z.array(z.string()),
      }),
    }),
  }),
);

export const itWalletCredentialIssuerMetadata = z
  .object({
    credential_issuer: z.string().url(),
    credential_endpoint: z.string().url(),
    nonce_endpoint: z.string().url(),
    revocation_endpoint: z.string().url(),
    deferred_credential_endpoint: z.string().url(),
    status_assertion_endpoint: z.string().url(),
    status_attestation_endpoint: z.string().url(),
    notification_endpoint: z.string().url(),
    authorization_servers: z.array(z.string().url()).optional(),
    display: z.array(CredentialDisplayMetadata),
    credential_configurations_supported: z.record(SupportedCredentialMetadata),
    jwks: JWKS,
    trust_frameworks_supported: z.array(
      z.union([
        z.literal("it_cie"),
        z.literal("it_wallet"),
        z.literal("eudi_wallet"),
      ]),
    ),
    evidence_supported: z
      .array(z.string())
      .refine((arr) => arr.includes("vouch"), {
        message: "The evidence_supported array MUST include 'vouch'.",
      }),
    credential_hash_alg_supported: z.string(),
    batch_credential_issuance: z.object({
      batch_size: z.number().int(),
    }),
  })
  .passthrough();

export type ItWalletCredentialIssuerMetadata = z.input<
  typeof itWalletCredentialIssuerMetadata
>;

export const itWalletCredentialIssuerIdentifier = "openid_credential_issuer";
