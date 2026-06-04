import type { CallbackContext } from "@openid4vc/oauth2";
import type {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import type {
  CredentialOfferV1_3,
  CredentialOfferV1_4,
} from "./z-credential-offer";

/**
 * Options for parsing a credential offer URI.
 *
 * Version-agnostic: IT-Wallet v1.3 and v1.4 share the same invocation schemes.
 */
export interface ParseCredentialOfferUriOptions {
  /**
   * Allowed URL schemes for the credential offer URI.
   *
   * Defaults to: ["openid-credential-offer", "haip-vci", "https"]
   *
   * @default ["openid-credential-offer", "haip-vci", "https"]
   */
  allowedSchemes?: string[];

  /**
   * The credential offer URI to parse.
   *
   * Supported formats:
   * - Custom URL schemes:
   *   - openid-credential-offer://?credential_offer=...
   *   - openid-credential-offer://?credential_offer_uri=https://...
   *   - haip-vci://?credential_offer=...
   *   - haip-vci://?credential_offer_uri=https://...
   *
   * - HTTPS Universal Links (preferred):
   *   - https://wallet.example.com/credential-offer?credential_offer=...
   *   - https://wallet.example.com/credential-offer?credential_offer_uri=https://...
   *
   * @example
   * // By value with custom scheme
   * const uri1 = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A...";
   *
   * // By reference with HTTPS Universal Link
   * const uri2 = "https://wallet.example.com/credential-offer?credential_offer_uri=https://issuer.example.com/offers/123";
   */
  uri: string;
}

/**
 * Base options shared across all resolve-credential-offer versions.
 */
interface BaseResolveCredentialOfferOptions {
  /**
   * Callback context with fetch implementation.
   *
   * Required for resolving credential offers by reference (credential_offer_uri).
   * The fetch function will be used to retrieve the credential offer from the remote URL.
   */
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * The credential offer to resolve.
   *
   * Can be:
   * - A credential offer URI (openid-credential-offer://, haip-vci://, or https://)
   * - A direct JSON string representation of the credential offer
   *
   * @example
   * // URI by value
   * const offer1 = "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A...";
   *
   * // URI by reference
   * const offer2 = "haip-vci://?credential_offer_uri=https://issuer.example.com/offers/123";
   *
   * // Direct JSON
   * const offer3 = '{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":["UniversityDegree"],"grants":{"authorization_code":{"scope":"openid"}}}';
   */
  credentialOffer: string;
}

/**
 * Options for resolving a credential offer against the IT-Wallet v1.3 schema.
 */
export interface ResolveCredentialOfferOptionsV1_3 extends BaseResolveCredentialOfferOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>;
}

/**
 * Options for resolving a credential offer against the IT-Wallet v1.4 schema.
 */
export interface ResolveCredentialOfferOptionsV1_4 extends BaseResolveCredentialOfferOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
}

/**
 * Options for resolving a credential offer.
 * The configured version selects the schema used to parse the offer.
 */
export type ResolveCredentialOfferOptions =
  | ResolveCredentialOfferOptionsV1_3
  | ResolveCredentialOfferOptionsV1_4;

/**
 * Base options shared across all validate-credential-offer versions.
 */
interface BaseValidateCredentialOfferOptions {
  /**
   * Optional Credential Issuer metadata for conditional validation.
   *
   * Used to validate the authorization_server requirement:
   * - If the Credential Issuer uses multiple Authorization Servers,
   *   authorization_server MUST be present in the grant and must match
   *   one of the authorization_servers in the metadata.
   *
   * @example
   * const metadata = {
   *   authorization_servers: [
   *     "https://auth1.issuer.example.com",
   *     "https://auth2.issuer.example.com"
   *   ]
   * };
   */
  credentialIssuerMetadata?: {
    authorization_servers?: string[];
  };
}

/**
 * Options for validating an IT-Wallet v1.3 credential offer.
 */
export interface ValidateCredentialOfferOptionsV1_3 extends BaseValidateCredentialOfferOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>;
  /**
   * The credential offer to validate against IT-Wallet v1.3 specifications.
   */
  credentialOffer: CredentialOfferV1_3;
}

/**
 * Options for validating an IT-Wallet v1.4 credential offer.
 */
export interface ValidateCredentialOfferOptionsV1_4 extends BaseValidateCredentialOfferOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
  /**
   * The credential offer to validate against IT-Wallet v1.4 specifications.
   */
  credentialOffer: CredentialOfferV1_4;
}

/**
 * Options for validating a credential offer against IT-Wallet specifications.
 */
export type ValidateCredentialOfferOptions =
  | ValidateCredentialOfferOptionsV1_3
  | ValidateCredentialOfferOptionsV1_4;

/**
 * Options for extracting grant details from an IT-Wallet v1.3 credential offer.
 */
export interface ExtractGrantDetailsOptionsV1_3 {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>;
  /**
   * The credential offer to extract grant details from.
   */
  credentialOffer: CredentialOfferV1_3;
}

/**
 * Options for extracting grant details from an IT-Wallet v1.4 credential offer.
 */
export interface ExtractGrantDetailsOptionsV1_4 {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
  /**
   * The credential offer to extract grant details from.
   */
  credentialOffer: CredentialOfferV1_4;
}

/**
 * Options for extracting grant details from a credential offer.
 */
export type ExtractGrantDetailsOptions =
  | ExtractGrantDetailsOptionsV1_3
  | ExtractGrantDetailsOptionsV1_4;

/**
 * Result of extracting grant details from an IT-Wallet v1.3 credential offer.
 */
export interface ExtractGrantDetailsResultV1_3 {
  /**
   * Details of the authorization code grant.
   */
  authorizationCodeGrant: {
    /**
     * HTTPS URL of the Authorization Server.
     * OPTIONAL, but REQUIRED when the Credential Issuer uses multiple Authorization Servers.
     */
    authorizationServer?: string;

    /**
     * String value representing the issuer state.
     * OPTIONAL. Used to correlate the authorization request with the credential offer.
     */
    issuerState?: string;

    /**
     * OAuth 2.0 scope value.
     * REQUIRED in IT-Wallet v1.3.
     */
    scope: string;
  };

  /**
   * The type of grant present in the credential offer.
   * IT-Wallet only supports "authorization_code".
   */
  grantType: "authorization_code";
}

/**
 * Result of extracting grant details from an IT-Wallet v1.4 credential offer.
 *
 * Difference from v1.3: the credential offer no longer carries a `scope`;
 * the wallet derives it from the credential configuration metadata instead.
 */
export interface ExtractGrantDetailsResultV1_4 {
  /**
   * Details of the authorization code grant.
   */
  authorizationCodeGrant: {
    /**
     * HTTPS URL of the Authorization Server.
     * OPTIONAL, but REQUIRED when the Credential Issuer uses multiple Authorization Servers.
     */
    authorizationServer?: string;

    /**
     * String value representing the issuer state.
     * OPTIONAL. Used to correlate the authorization request with the credential offer.
     */
    issuerState?: string;
  };

  /**
   * The type of grant present in the credential offer.
   * IT-Wallet only supports "authorization_code".
   */
  grantType: "authorization_code";
}

/**
 * Result of extracting grant details from a credential offer.
 */
export type ExtractGrantDetailsResult =
  | ExtractGrantDetailsResultV1_3
  | ExtractGrantDetailsResultV1_4;
