import { z } from "zod";

/**
 * Transaction Code schema
 *
 * Object indicating that a Transaction Code is required if present, even if empty.
 * It describes the requirements for a Transaction Code, which the Authorization Server expects
 * the End-User to present along with the Token Request in a Pre-Authorized Code Flow.
 * If the Authorization Server does not expect a Transaction Code, this object is absent;
 */
export const zTxCodePreAuthorizedCodeGrantAPTITUDE = z.object({
  /**
   * OPTIONAL. String containing guidance for the Holder
   * of the Wallet on how to obtain the Transaction Code.
   */
  description: z.string().max(300).optional(),

  /**
   * OPTIONAL. String specifying the input character set.
   * Possible values are numeric (only digits) and text (any characters).
   * The default is numeric.
   */
  input_mode: z.enum(["numeric", "digit"]).optional(),

  /**
   * OPTIONAL. Integer specifying the length of the Transaction Code.
   */
  length: z.number().optional(),
});

/**
 * Authorization Code Grant schema
 * IT-Wallet v1.4 specification: Section 5.1
 *
 * Difference from v1.4: the pre-authorized_code grant is now supported.
 * The authorization_code grant is NOT REQUIRED anymore.
 */
export const zAuthorizationCodeGrantAPTITUDE = z.object({
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
});

/**
 * Pre-Authorized Code Grant schema
 *
 * Grant schema for Pre-Authorized Code Flow. Only pre-authorized_code key is REQUIRED.
 */
export const zPreAuthorizedCodeGrantAPTITUDE = z.object({
  /**
   * CONDITIONALLY REQUIRED. HTTPS URL of the Authorization Server.
   * REQUIRED only when the Credential Issuer uses multiple Authorization Servers.
   * If present, MUST match one of the authorization_servers in the Credential Issuer metadata.
   */
  authorization_server: z.url().optional(),

  /**
   * REQUIRED. The code representing the Credential Issuer's authorization for
   * the Wallet to obtain Credentials of a certain type
   */
  "pre-authorized_code": z.string(),

  /**
   * OPTIONAL. Object indicating that a Transaction Code is required if present, even if empty.
   * It describes the requirements for a Transaction Code, which the Authorization Server expects
   * the End-User to present along with the Token Request in a Pre-Authorized Code Flow.
   * If the Authorization Server does not expect a Transaction Code, this object is absent;
   */
  tx_code: zTxCodePreAuthorizedCodeGrantAPTITUDE.optional(),
});

/**
 * Credential Offer Grants schema
 * IT-Wallet v1.4 specification: Section 5.1
 *
 * The grants object is REQUIRED for IT-Wallet v1.4.
 */
export const zCredentialOfferGrantsAPTITUDE = z.object({
  /**
   * OPTIONAL. Authorization Code grant details.
   */
  authorization_code: zAuthorizationCodeGrantAPTITUDE.optional(),

  /**
   * OPTIONAL. Pre-Authorized Code grant details.
   */
  "urn:ietf:params:oauth:grant-type:pre-authorized_code":
    zPreAuthorizedCodeGrantAPTITUDE.optional(),
});

/**
 * Credential Offer schema
 * IT-Wallet v1.4 specification: Section 5.1
 *
 * Represents a credential offer from a Credential Issuer to a wallet.
 */
export const zCredentialOfferAPTITUDE = z.object({
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
   * IT-Wallet v1.4 requires authorization_code or pre-auhorized code grant.
   */
  grants: zCredentialOfferGrantsAPTITUDE,
});

export type TxCodePreAuthorizedCodeGrantAPTITUDE = z.infer<
  typeof zTxCodePreAuthorizedCodeGrantAPTITUDE
>;

export type PreAuthorizedCodeGrantAPTITUDE = z.infer<
  typeof zPreAuthorizedCodeGrantAPTITUDE
>;

export type AuthorizationCodeGrantAPTITUDE = z.infer<
  typeof zAuthorizationCodeGrantAPTITUDE
>;
export type CredentialOfferGrantsAPTITUDE = z.infer<
  typeof zCredentialOfferGrantsAPTITUDE
>;
export type CredentialOfferAPTITUDE = z.infer<typeof zCredentialOfferAPTITUDE>;

/**
 * TypeScript enum for Credential Offer Supported Grants
 */
export enum CREDENTIAL_OFFER_GRANTS {
  AUTHORIZATION_CODE = "authorization_code",
  PREAUTHORIZED_CODE = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
}
