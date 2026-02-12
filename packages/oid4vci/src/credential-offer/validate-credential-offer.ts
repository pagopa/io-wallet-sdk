import type { ValidateCredentialOfferOptions } from "./types";

import { CredentialOfferError } from "../errors";

/**
 * Validates a credential offer against IT-Wallet v1.3 specifications.
 *
 * This function performs comprehensive validation of a credential offer to ensure
 * compliance with the IT-Wallet v1.3 requirements (Section 5.1):
 *
 * **Required validations:**
 * - `credential_issuer` must be an HTTPS URL
 * - `credential_configuration_ids` must contain at least one identifier
 * - `grants` object is REQUIRED for IT-Wallet v1.3
 * - `authorization_code` grant is REQUIRED (pre-authorized code is NOT supported)
 * - `scope` is REQUIRED within the authorization_code grant
 *
 * **Conditional validations:**
 * - `authorization_server` is REQUIRED when the Credential Issuer uses multiple Authorization Servers
 * - If `authorization_server` is present, it MUST match one of the servers in the Credential Issuer metadata
 *
 * @param options - Validation options containing the credential offer, config, and optional metadata
 * @throws {CredentialOfferError} If any validation rule fails
 */
export async function validateCredentialOffer(
  options: ValidateCredentialOfferOptions,
): Promise<void> {
  const { credentialIssuerMetadata, credentialOffer } = options;

  // Validate credential_issuer is HTTPS
  if (!credentialOffer.credential_issuer.startsWith("https://")) {
    throw new CredentialOfferError("credential_issuer must be an HTTPS URL");
  }

  // Validate credential_configuration_ids is not empty
  if (credentialOffer.credential_configuration_ids.length === 0) {
    throw new CredentialOfferError(
      "credential_configuration_ids must contain at least one identifier",
    );
  }

  // IT-Wallet v1.3: grants is REQUIRED
  if (!credentialOffer.grants) {
    throw new CredentialOfferError("grants is REQUIRED for IT-Wallet v1.3");
  }

  const authCodeGrant = credentialOffer.grants.authorization_code;

  // IT-Wallet v1.3: authorization_code grant is REQUIRED
  if (!authCodeGrant) {
    throw new CredentialOfferError(
      "authorization_code grant is REQUIRED for IT-Wallet v1.3",
    );
  }

  // Validate scope is present (REQUIRED in authorization_code)
  if (!authCodeGrant.scope) {
    throw new CredentialOfferError("authorization_code.scope is REQUIRED");
  }

  // Conditional validation for authorization_server
  // REQUIRED only when CI uses multiple authorization servers
  if (credentialIssuerMetadata?.authorization_servers) {
    const authServers = credentialIssuerMetadata.authorization_servers;

    // If multiple authorization servers exist, authorization_server must be present
    if (authServers.length > 1 && !authCodeGrant.authorization_server) {
      throw new CredentialOfferError(
        "authorization_server is REQUIRED when Credential Issuer uses multiple Authorization Servers",
      );
    }

    // If authorization_server is present, validate it matches metadata
    if (authCodeGrant.authorization_server) {
      if (!authServers.includes(authCodeGrant.authorization_server)) {
        throw new CredentialOfferError(
          `authorization_server '${authCodeGrant.authorization_server}' does not match Credential Issuer metadata. Valid servers: ${authServers.join(", ")}`,
        );
      }
    }
  }
}
