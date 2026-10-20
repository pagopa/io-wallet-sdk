import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  createVersionDispatcher,
} from "@pagopa/io-wallet-utils";

import type {
  ExtractGrantDetailsOptions,
  ExtractGrantDetailsOptionsAPTITUDE,
  ExtractGrantDetailsOptionsV1_3,
  ExtractGrantDetailsOptionsV1_4,
  ExtractGrantDetailsResult,
  ExtractGrantDetailsResultAPTITUDE,
  ExtractGrantDetailsResultV1_3,
  ExtractGrantDetailsResultV1_4,
} from "./types";

import { CredentialOfferError } from "../errors";
import {
  CREDENTIAL_OFFER_GRANTS,
  CredentialOfferAPTITUDE,
} from "./APTITUDE/z-credential-offer";
import {
  type AuthorizationCodeGrantV1_3,
  type AuthorizationCodeGrantV1_4,
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
 * Resolves the authorization_code and pre-authorized_code grant object from a credential offer, enforcing that at least one is present.
 *
 * @throws {CredentialOfferError} If grants or the either authorization_code or pre-authorized_code grants are missing.
 */
function requireAuthorizationCodeOrPreAuthorizedCodeGrant(
  credentialOffer: CredentialOfferAPTITUDE,
): CredentialOfferAPTITUDE["grants"] {
  if (!credentialOffer.grants) {
    throw new CredentialOfferError("No grants found in credential offer");
  }

  const grants = credentialOffer.grants;

  if (
    !grants[CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE] &&
    !grants[CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE]
  ) {
    throw new CredentialOfferError(
      "either one of authorization_code or pre-authorized code grant is required",
    );
  }

  return grants;
}

function extractGrantDetailsV1_3(
  options: ExtractGrantDetailsOptionsV1_3,
): ExtractGrantDetailsResultV1_3 {
  const authCodeGrant = requireAuthorizationCodeGrant(options.credentialOffer);

  return {
    [CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE]: {
      authorizationServer: authCodeGrant.authorization_server,
      issuerState: authCodeGrant.issuer_state,
      scope: authCodeGrant.scope,
    },
  };
}

function extractGrantDetailsV1_4(
  options: ExtractGrantDetailsOptionsV1_4,
): ExtractGrantDetailsResultV1_4 {
  const authCodeGrant = requireAuthorizationCodeGrant(options.credentialOffer);

  return {
    [CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE]: {
      authorizationServer: authCodeGrant.authorization_server,
      issuerState: authCodeGrant.issuer_state,
    },
  };
}

function extractGrantDetailsAPTITUDE(
  options: ExtractGrantDetailsOptionsAPTITUDE,
): ExtractGrantDetailsResultAPTITUDE {
  const grants = requireAuthorizationCodeOrPreAuthorizedCodeGrant(
    options.credentialOffer,
  );

  const authorizationCodeGrant =
    grants[CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE];
  const preAuthorizedCodeGrant =
    grants[CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE];

  return {
    ...(authorizationCodeGrant && {
      [CREDENTIAL_OFFER_GRANTS.AUTHORIZATION_CODE]: {
        authorizationServer: authorizationCodeGrant.authorization_server,
        issuerState: authorizationCodeGrant.issuer_state,
      },
    }),
    ...(preAuthorizedCodeGrant && {
      [CREDENTIAL_OFFER_GRANTS.PREAUTHORIZED_CODE]: {
        authorizationServer: preAuthorizedCodeGrant.authorization_server,
        preAuthorizedCode: preAuthorizedCodeGrant["pre-authorized_code"],
        txCode: preAuthorizedCodeGrant.tx_code,
      },
    }),
  };
}

const dispatchExtractGrantDetails = createVersionDispatcher<
  ExtractGrantDetailsOptions,
  ExtractGrantDetailsResult
>({
  [ItWalletSpecsVersion.APTITUDE]: (o) =>
    extractGrantDetailsAPTITUDE(o as ExtractGrantDetailsOptionsAPTITUDE),
  [ItWalletSpecsVersion.V1_0]: () => {
    throw new ItWalletSpecsVersionError(
      "extractGrantDetails",
      ItWalletSpecsVersion.V1_0,
      [
        ItWalletSpecsVersion.V1_3,
        ItWalletSpecsVersion.V1_4,
        ItWalletSpecsVersion.APTITUDE,
      ],
    );
  },
  [ItWalletSpecsVersion.V1_3]: (o) =>
    extractGrantDetailsV1_3(o as ExtractGrantDetailsOptionsV1_3),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    extractGrantDetailsV1_4(o as ExtractGrantDetailsOptionsV1_4),
});

/**
 * Extracts grant details from a credential offer according to the configured
 * Italian Wallet specification version. Returns version-specific grant details keyed by grant type.
 *
 *
 * Version Differences:
 * - v1.3: extracts `scope` (REQUIRED), `authorization_server` (OPTIONAL), `issuer_state` (OPTIONAL)
 * - v1.4: extracts `authorization_server` (OPTIONAL) and `issuer_state` (OPTIONAL); the
 *   credential offer no longer carries a `scope`.
 * - APTITUDE: extracts `authorization_server` (OPTIONAL), `pre-authorized_code` (REQUIRED), and `tx_code` (OPTIONAL).
 *   authorization_code properties are not mandatory anymore.
 *
 *
 * @param options - Extraction options including the credential offer and version config
 * @returns Version-specific grant details keyed by grant type.
 * @throws {CredentialOfferError} If grants or the either authorization_code or pre-authorized_code grants are missing
 * @throws {ItWalletSpecsVersionError} If the configured version does not support credential offers
 */
export function extractGrantDetails(
  options: ExtractGrantDetailsOptionsV1_3,
): ExtractGrantDetailsResultV1_3;

export function extractGrantDetails(
  options: ExtractGrantDetailsOptionsV1_4,
): ExtractGrantDetailsResultV1_4;

export function extractGrantDetails(
  options: ExtractGrantDetailsOptionsAPTITUDE,
): ExtractGrantDetailsResultAPTITUDE;

export function extractGrantDetails(
  options: ExtractGrantDetailsOptions,
): ExtractGrantDetailsResult;

export function extractGrantDetails(
  options: ExtractGrantDetailsOptions,
): ExtractGrantDetailsResult {
  return dispatchExtractGrantDetails(options);
}
