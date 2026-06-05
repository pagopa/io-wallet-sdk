import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  createVersionDispatcher,
} from "@pagopa/io-wallet-utils";

import type {
  ExtractGrantDetailsOptions,
  ExtractGrantDetailsOptionsV1_3,
  ExtractGrantDetailsOptionsV1_4,
  ExtractGrantDetailsResult,
  ExtractGrantDetailsResultV1_3,
  ExtractGrantDetailsResultV1_4,
} from "./types";
import type {
  AuthorizationCodeGrantV1_3,
  AuthorizationCodeGrantV1_4,
} from "./z-credential-offer";

import { CredentialOfferError } from "../errors";

/**
 * Resolves the authorization_code grant from a credential offer, enforcing its presence.
 *
 * @throws {CredentialOfferError} If grants or the authorization_code grant is missing.
 */
function requireAuthorizationCodeGrant<
  TGrant extends AuthorizationCodeGrantV1_3 | AuthorizationCodeGrantV1_4,
>(credentialOffer: { grants?: { authorization_code?: TGrant } }): TGrant {
  if (!credentialOffer.grants) {
    throw new CredentialOfferError("No grants found in credential offer");
  }

  const authCodeGrant = credentialOffer.grants.authorization_code;

  if (!authCodeGrant) {
    throw new CredentialOfferError("authorization_code grant not found");
  }

  return authCodeGrant;
}

function extractGrantDetailsV1_3(
  options: ExtractGrantDetailsOptionsV1_3,
): ExtractGrantDetailsResultV1_3 {
  const authCodeGrant = requireAuthorizationCodeGrant(options.credentialOffer);

  return {
    authorizationCodeGrant: {
      authorizationServer: authCodeGrant.authorization_server,
      issuerState: authCodeGrant.issuer_state,
      scope: authCodeGrant.scope,
    },
    grantType: "authorization_code",
  };
}

function extractGrantDetailsV1_4(
  options: ExtractGrantDetailsOptionsV1_4,
): ExtractGrantDetailsResultV1_4 {
  const authCodeGrant = requireAuthorizationCodeGrant(options.credentialOffer);

  return {
    authorizationCodeGrant: {
      authorizationServer: authCodeGrant.authorization_server,
      issuerState: authCodeGrant.issuer_state,
    },
    grantType: "authorization_code",
  };
}

const dispatchExtractGrantDetails = createVersionDispatcher<
  ExtractGrantDetailsOptions,
  ExtractGrantDetailsResult
>({
  [ItWalletSpecsVersion.V1_0]: () => {
    throw new ItWalletSpecsVersionError(
      "extractGrantDetails",
      ItWalletSpecsVersion.V1_0,
      [ItWalletSpecsVersion.V1_3, ItWalletSpecsVersion.V1_4],
    );
  },
  [ItWalletSpecsVersion.V1_3]: (o) =>
    extractGrantDetailsV1_3(o as ExtractGrantDetailsOptionsV1_3),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    extractGrantDetailsV1_4(o as ExtractGrantDetailsOptionsV1_4),
});

/**
 * Extracts grant details from a credential offer according to the configured
 * Italian Wallet specification version.
 *
 * IT-Wallet only supports the `authorization_code` grant type. Pre-authorized
 * code grants are NOT supported.
 *
 * Version Differences:
 * - v1.3: extracts `scope` (REQUIRED), `authorization_server` (OPTIONAL), `issuer_state` (OPTIONAL)
 * - v1.4: extracts `authorization_server` (OPTIONAL) and `issuer_state` (OPTIONAL); the
 *   credential offer no longer carries a `scope`
 *
 * @param options - Extraction options including the credential offer and version config
 * @returns Version-specific grant details containing the grant type and authorization code grant information
 * @throws {CredentialOfferError} If grants or the authorization_code grant is missing
 * @throws {ItWalletSpecsVersionError} If the configured version does not support credential offers
 */
export function extractGrantDetails(
  options: ExtractGrantDetailsOptionsV1_3,
): ExtractGrantDetailsResultV1_3;

export function extractGrantDetails(
  options: ExtractGrantDetailsOptionsV1_4,
): ExtractGrantDetailsResultV1_4;

export function extractGrantDetails(
  options: ExtractGrantDetailsOptions,
): ExtractGrantDetailsResult {
  return dispatchExtractGrantDetails(options);
}
