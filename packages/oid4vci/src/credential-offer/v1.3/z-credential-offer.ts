import { z } from "zod";

/**
 * Authorization Code Grant schema
 * IT-Wallet v1.3 specification: Section 5.1
 *
 * The authorization_code grant is REQUIRED for IT-Wallet v1.3.
 * Pre-authorized code grant is NOT supported.
 */
export const zAuthorizationCodeGrantV1_3 = z.object({
  /**
   * CONDITIONALLY REQUIRED. HTTPS URL of the Authorization Server.
   * REQUIRED only when the Credential Issuer uses multiple Authorization Servers.
   * If present, MUST match one of the authorization_servers in the Credential Issuer metadata.
   */
  authorization_server: z.url().optional(),

  /**
   * OPTIONAL. String value representing the issuer state.
   * Used to correlate the authorization request with the credential offer.
   */
  issuer_state: z.string().optional(),

  /**
   * REQUIRED. OAuth 2.0 scope value.
   * Defines the scope of access requested by the credential offer.
   */
  scope: z.string(),
});

/**
 * Credential Offer Grants schema
 * IT-Wallet v1.3 specification: Section 5.1
 *
 * The grants object is REQUIRED for IT-Wallet v1.3.
 * Only authorization_code grant is supported.
 */
export const zCredentialOfferGrantsV1_3 = z.object({
  /**
   * REQUIRED. Authorization Code grant details.
   * IT-Wallet v1.3 only supports authorization_code grant.
   */
  authorization_code: zAuthorizationCodeGrantV1_3,
});

/**
 * Credential Offer schema
 * IT-Wallet v1.3 specification: Section 5.1
 *
 * Represents a credential offer from a Credential Issuer to a wallet.
 */
export const zCredentialOfferV1_3 = z.object({
  /**
   * REQUIRED. Array of credential configuration identifiers.
   * References the types of credentials offered as defined in the Credential Issuer metadata.
   */
  credential_configuration_ids: z.array(z.string()).min(1),

  /**
   * REQUIRED. HTTPS URL of the Credential Issuer.
   * The Credential Issuer from which the wallet will request credentials.
   */
  credential_issuer: z.url(),

  /**
   * REQUIRED. Grant information for the credential offer.
   * IT-Wallet v1.3 requires authorization_code grant.
   */
  grants: zCredentialOfferGrantsV1_3,
});

export type AuthorizationCodeGrantV1_3 = z.infer<
  typeof zAuthorizationCodeGrantV1_3
>;
export type CredentialOfferGrantsV1_3 = z.infer<
  typeof zCredentialOfferGrantsV1_3
>;
export type CredentialOfferV1_3 = z.infer<typeof zCredentialOfferV1_3>;
