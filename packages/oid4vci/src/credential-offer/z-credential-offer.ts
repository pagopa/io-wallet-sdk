import { z } from "zod";

/**
 * Authorization Code Grant schema
 * IT-Wallet v1.3 specification: Section 5.1
 *
 * The authorization_code grant is REQUIRED for IT-Wallet v1.3.
 * Pre-authorized code grant is NOT supported.
 */
export const zAuthorizationCodeGrant = z.object({
  /**
   * CONDITIONALLY REQUIRED. HTTPS URL of the Authorization Server.
   * REQUIRED only when the Credential Issuer uses multiple Authorization Servers.
   * If present, MUST match one of the authorization_servers in the Credential Issuer metadata.
   */
  authorization_server: z.string().url().optional(),

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
export const zCredentialOfferGrants = z.object({
  /**
   * REQUIRED. Authorization Code grant details.
   * IT-Wallet v1.3 only supports authorization_code grant.
   */
  authorization_code: zAuthorizationCodeGrant,
});

/**
 * Credential Offer schema
 * IT-Wallet v1.3 specification: Section 5.1
 *
 * Represents a credential offer from a Credential Issuer to a wallet.
 */
export const zCredentialOffer = z.object({
  /**
   * REQUIRED. Array of credential configuration identifiers.
   * References the types of credentials offered as defined in the Credential Issuer metadata.
   */
  credential_configuration_ids: z.array(z.string()).min(1),

  /**
   * REQUIRED. HTTPS URL of the Credential Issuer.
   * The Credential Issuer from which the wallet will request credentials.
   */
  credential_issuer: z.string().url(),

  /**
   * REQUIRED. Grant information for the credential offer.
   * IT-Wallet v1.3 requires authorization_code grant.
   */
  grants: zCredentialOfferGrants,
});

/**
 * Credential Offer URI schema
 * Represents a parsed credential offer URI with scheme and parameters.
 *
 * Supports three URL schemes:
 * - openid-credential-offer:// - Standard OpenID scheme (custom URL scheme)
 * - haip-vci:// - High Assurance Interoperability Profile scheme (custom URL scheme)
 * - https:// - HTTPS Universal Links (preferred method)
 *
 * Transmission methods:
 * - By value: credential_offer parameter contains the JSON directly
 * - By reference: credential_offer_uri parameter points to the JSON
 */
export const zCredentialOfferUri = z
  .object({
    /**
     * OPTIONAL. Inline credential offer JSON (by value).
     * URL-encoded JSON string containing the credential offer.
     */
    credential_offer: z.string().optional(),

    /**
     * OPTIONAL. URL pointing to the credential offer JSON (by reference).
     * HTTPS URL where the credential offer can be fetched.
     */
    credential_offer_uri: z.string().url().optional(),

    /**
     * URL scheme used for the credential offer.
     * Determines the invocation method.
     */
    scheme: z.enum(["openid-credential-offer", "haip-vci", "https"]),
  })
  .refine((data) => data.credential_offer || data.credential_offer_uri, {
    message: "Either credential_offer or credential_offer_uri must be present",
  });

/**
 * TypeScript type for Authorization Code Grant
 */
export type AuthorizationCodeGrant = z.infer<typeof zAuthorizationCodeGrant>;

/**
 * TypeScript type for Credential Offer Grants
 */
export type CredentialOfferGrants = z.infer<typeof zCredentialOfferGrants>;

/**
 * TypeScript type for Credential Offer
 */
export type CredentialOffer = z.infer<typeof zCredentialOffer>;

/**
 * TypeScript type for Credential Offer URI
 */
export type CredentialOfferUri = z.infer<typeof zCredentialOfferUri>;
