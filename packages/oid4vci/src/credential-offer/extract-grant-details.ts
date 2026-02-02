import type { ExtractGrantDetailsResult } from "./types";
import type { CredentialOffer } from "./z-credential-offer";

import { CredentialOfferError } from "../errors";

/**
 * Extracts grant details from a credential offer.
 *
 * IT-Wallet v1.3 only supports the `authorization_code` grant type.
 * Pre-authorized code grants are NOT supported.
 *
 * This function extracts:
 * - Grant type (always "authorization_code" for IT-Wallet)
 * - Scope (REQUIRED)
 * - Authorization server (OPTIONAL, but REQUIRED when CI uses multiple auth servers)
 * - Issuer state (OPTIONAL)
 *
 * @param credentialOffer - The credential offer to extract grant details from
 * @returns Grant details containing the grant type and authorization code grant information
 * @throws {CredentialOfferError} If grants or authorization_code grant is missing
 */
export function extractGrantDetails(
  credentialOffer: CredentialOffer,
): ExtractGrantDetailsResult {
  if (!credentialOffer.grants) {
    throw new CredentialOfferError("No grants found in credential offer");
  }

  const authCodeGrant = credentialOffer.grants.authorization_code;

  if (!authCodeGrant) {
    throw new CredentialOfferError("authorization_code grant not found");
  }

  return {
    authorizationCodeGrant: {
      authorizationServer: authCodeGrant.authorization_server,
      issuerState: authCodeGrant.issuer_state,
      scope: authCodeGrant.scope,
    },
    grantType: "authorization_code",
  };
}
