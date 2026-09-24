import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  createVersionDispatcher,
} from "@pagopa/io-wallet-utils";

import type {
  ExtractGrantDetailsOptions,
  ExtractGrantDetailsOptionsV1_3,
  ExtractGrantDetailsOptionsV1_4,
  ExtractGrantDetailsOptionsV1_5,
  ExtractGrantDetailsResult,
  ExtractGrantDetailsResultV1_3,
  ExtractGrantDetailsResultV1_4,
  ExtractGrantDetailsResultV1_5,
} from "./types";

import { CredentialOfferError } from "../errors";
import { CREDENTIAL_OFFER_GRANTS } from "./v1.5/z-credential-offer";
import {
  type AuthorizationCodeGrantV1_3,
  type AuthorizationCodeGrantV1_4,
  type AuthorizationCodeGrantV1_5,
  type CredentialOfferV1_5,
  type PreAuthorizedCodeGrantV1_5,
} from "./z-credential-offer";

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

/**
 * Resolves the authorization_code grant from a credential offer, enforcing its presence.
 *
 * @throws {CredentialOfferError} If grants or the either authorization_code or pre-authorized_code grants are missing.
 */
function requireAuthorizationCodeOrPreAuthorizedCodeGrant(
  credentialOffer: CredentialOfferV1_5,
): AuthorizationCodeGrantV1_5 | PreAuthorizedCodeGrantV1_5 {
  if (!credentialOffer.grants) {
    throw new CredentialOfferError("No grants found in credential offer");
  }

  if (
    CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE in credentialOffer.grants &&
    CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE in credentialOffer.grants
  ) {
    throw new CredentialOfferError(
      "both authorization_code and pre-authorized_code grants are not supported simultaneously",
    );
  }

  let authCodeGrant;

  if (CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE in credentialOffer.grants) {
    authCodeGrant =
      credentialOffer.grants[CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE];
  }

  if (CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE in credentialOffer.grants) {
    authCodeGrant =
      credentialOffer.grants[CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE];
  }

  if (!authCodeGrant) {
    throw new CredentialOfferError(
      "either one of authorization_code or pre-authorized code grant is required",
    );
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

function extractGrantDetailsV1_5(
  options: ExtractGrantDetailsOptionsV1_5,
): ExtractGrantDetailsResultV1_5 {
  const authCodeGrant = requireAuthorizationCodeOrPreAuthorizedCodeGrant(
    options.credentialOffer,
  );

  if ("pre-authorized_code" in authCodeGrant) {
    return {
      grantType: CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE,
      preAuthorizedCodeGrant: {
        authorizationServer: authCodeGrant.authorization_server,
        preAuthorizedCode: authCodeGrant["pre-authorized_code"],
        txCode: authCodeGrant.tx_code,
      },
    };
  }

  return {
    authorizationCodeGrant: {
      authorizationServer: authCodeGrant.authorization_server,
      issuerState: authCodeGrant.issuer_state,
    },
    grantType: CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE,
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
      [
        ItWalletSpecsVersion.V1_3,
        ItWalletSpecsVersion.V1_4,
        ItWalletSpecsVersion.V1_5,
      ],
    );
  },
  [ItWalletSpecsVersion.V1_3]: (o) =>
    extractGrantDetailsV1_3(o as ExtractGrantDetailsOptionsV1_3),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    extractGrantDetailsV1_4(o as ExtractGrantDetailsOptionsV1_4),
  [ItWalletSpecsVersion.V1_5]: (o) =>
    extractGrantDetailsV1_5(o as ExtractGrantDetailsOptionsV1_5),
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
  options: ExtractGrantDetailsOptionsV1_5,
): ExtractGrantDetailsResultV1_5;

export function extractGrantDetails(
  options: ExtractGrantDetailsOptions,
): ExtractGrantDetailsResult;

export function extractGrantDetails(
  options: ExtractGrantDetailsOptions,
): ExtractGrantDetailsResult {
  return dispatchExtractGrantDetails(options);
}
