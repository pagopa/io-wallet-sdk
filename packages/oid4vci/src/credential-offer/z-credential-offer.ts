import { z } from "zod";

import {
  type AuthorizationCodeGrantV1_3,
  type CredentialOfferGrantsV1_3,
  type CredentialOfferV1_3,
  zAuthorizationCodeGrantV1_3,
  zCredentialOfferGrantsV1_3,
  zCredentialOfferV1_3,
} from "./v1.3/z-credential-offer";
import {
  type AuthorizationCodeGrantV1_4,
  type CredentialOfferGrantsV1_4,
  type CredentialOfferV1_4,
  zAuthorizationCodeGrantV1_4,
  zCredentialOfferGrantsV1_4,
  zCredentialOfferV1_4,
} from "./v1.4/z-credential-offer";

// Re-export version-specific schemas and types.
// v1.4 forks only the authorization_code grant (no `scope`); everything else is identical to v1.3.
export {
  zAuthorizationCodeGrantV1_3,
  zCredentialOfferGrantsV1_3,
  zCredentialOfferV1_3,
};
export {
  zAuthorizationCodeGrantV1_4,
  zCredentialOfferGrantsV1_4,
  zCredentialOfferV1_4,
};
export type {
  AuthorizationCodeGrantV1_3,
  CredentialOfferGrantsV1_3,
  CredentialOfferV1_3,
};
export type {
  AuthorizationCodeGrantV1_4,
  CredentialOfferGrantsV1_4,
  CredentialOfferV1_4,
};

/**
 * Credential Offer URI schema
 * Represents a parsed credential offer URI with scheme and parameters.
 *
 * Version-agnostic: IT-Wallet v1.3 and v1.4 share the same invocation schemes.
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
    credential_offer_uri: z.url().optional(),

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
 * TypeScript type for Authorization Code Grant.
 * Union across supported IT-Wallet versions.
 */
export type AuthorizationCodeGrant =
  | AuthorizationCodeGrantV1_3
  | AuthorizationCodeGrantV1_4;

/**
 * TypeScript type for Credential Offer Grants.
 * Union across supported IT-Wallet versions.
 */
export type CredentialOfferGrants =
  | CredentialOfferGrantsV1_3
  | CredentialOfferGrantsV1_4;

/**
 * TypeScript type for Credential Offer.
 * Union across supported IT-Wallet versions.
 */
export type CredentialOffer = CredentialOfferV1_3 | CredentialOfferV1_4;

/**
 * TypeScript type for Credential Offer URI
 */
export type CredentialOfferUri = z.infer<typeof zCredentialOfferUri>;
