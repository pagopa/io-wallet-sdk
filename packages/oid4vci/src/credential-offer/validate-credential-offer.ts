import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  createVersionDispatcher,
} from "@pagopa/io-wallet-utils";

import type {
  ValidateCredentialOfferOptions,
  ValidateCredentialOfferOptionsV1_3,
  ValidateCredentialOfferOptionsV1_4,
} from "./types";
import type { CredentialOffer } from "./z-credential-offer";

import { CredentialOfferError } from "../errors";

/**
 * Ensures an authorization server selected from a credential offer is one of the
 * `authorization_servers` declared by the Credential Issuer metadata.
 *
 * No-op when no authorization server was selected and the issuer specifies at least
 * two authorization servers. This check mirrors (and runs ahead of) the credential
 * offer validation step, so a metadata fetch driven by an offer fails fast on a
 * mismatched authorization server.
 *
 * @throws {CredentialOfferError} If a selected authorization server is absent
 *   from (or unsupported by) the issuer's `authorization_servers` list.
 */
export function assertAuthorizationServerAllowed(
  authorizationServer: string | undefined,
  authorizationServers: readonly [string, ...string[]] | undefined,
): void {
  if (!authorizationServer) {
    if (authorizationServers && authorizationServers.length > 1) {
      throw new CredentialOfferError(
        "authorization_server is REQUIRED when Credential Issuer uses multiple Authorization Servers",
      );
    }
    return;
  }

  if (!authorizationServers) {
    throw new CredentialOfferError(
      "credential offer specified an `authorization_server` but issuer metadata doesn't contain `authorization_servers`",
    );
  }

  if (authorizationServers.length === 1) {
    throw new CredentialOfferError(
      "credential offer specified an `authorization_server` but issuer metadata's `authorization_servers` contains only an element",
    );
  }

  if (!authorizationServers.includes(authorizationServer)) {
    throw new CredentialOfferError(
      `authorization_server '${authorizationServer}' does not match Credential Issuer metadata. Valid servers: ${authorizationServers.join(", ")}`,
    );
  }
}

/**
 * Validations shared across all IT-Wallet credential offer versions.
 *
 * @throws {CredentialOfferError} If any shared validation rule fails.
 */
function validateBaseCredentialOffer(options: {
  credentialIssuerMetadata?: { authorization_servers?: [string, ...string[]] };
  credentialOffer: CredentialOffer;
  versionLabel: string;
}): void {
  const { credentialIssuerMetadata, credentialOffer, versionLabel } = options;

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

  // grants is REQUIRED
  if (!credentialOffer.grants) {
    throw new CredentialOfferError(
      `grants is REQUIRED for IT-Wallet ${versionLabel}`,
    );
  }

  const authCodeGrant = credentialOffer.grants.authorization_code;

  // authorization_code grant is REQUIRED
  if (!authCodeGrant) {
    throw new CredentialOfferError(
      `authorization_code grant is REQUIRED for IT-Wallet ${versionLabel}`,
    );
  }

  assertAuthorizationServerAllowed(
    authCodeGrant.authorization_server,
    credentialIssuerMetadata?.authorization_servers,
  );
}

async function validateCredentialOfferV1_3(
  options: ValidateCredentialOfferOptionsV1_3,
): Promise<void> {
  validateBaseCredentialOffer({
    credentialIssuerMetadata: options.credentialIssuerMetadata,
    credentialOffer: options.credentialOffer,
    versionLabel: "v1.3",
  });

  // IT-Wallet v1.3: scope is REQUIRED within the authorization_code grant
  if (!options.credentialOffer.grants.authorization_code.scope) {
    throw new CredentialOfferError("authorization_code.scope is REQUIRED");
  }
}

async function validateCredentialOfferV1_4(
  options: ValidateCredentialOfferOptionsV1_4,
): Promise<void> {
  // IT-Wallet v1.4: the credential offer no longer carries a `scope`
  validateBaseCredentialOffer({
    credentialIssuerMetadata: options.credentialIssuerMetadata,
    credentialOffer: options.credentialOffer,
    versionLabel: "v1.4",
  });
}

const dispatchValidateCredentialOffer = createVersionDispatcher<
  ValidateCredentialOfferOptions,
  Promise<void>
>({
  [ItWalletSpecsVersion.V1_0]: () => {
    throw new ItWalletSpecsVersionError(
      "validateCredentialOffer",
      ItWalletSpecsVersion.V1_0,
      [ItWalletSpecsVersion.V1_3, ItWalletSpecsVersion.V1_4],
    );
  },
  [ItWalletSpecsVersion.V1_3]: (o) =>
    validateCredentialOfferV1_3(o as ValidateCredentialOfferOptionsV1_3),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    validateCredentialOfferV1_4(o as ValidateCredentialOfferOptionsV1_4),
});

/**
 * Validates a credential offer against IT-Wallet specifications for the configured version.
 *
 * **Required validations (all versions):**
 * - `credential_issuer` must be an HTTPS URL
 * - `credential_configuration_ids` must contain at least one identifier
 * - `grants` object is REQUIRED
 * - `authorization_code` grant is REQUIRED (pre-authorized code is NOT supported)
 *
 * **Version-specific validations:**
 * - v1.3: `scope` is REQUIRED within the authorization_code grant
 * - v1.4: the credential offer no longer carries a `scope`
 *
 * **Conditional validations:**
 * - `authorization_server` is REQUIRED when the Credential Issuer uses multiple Authorization Servers
 * - If `authorization_server` is present, it MUST match one of the servers in the Credential Issuer metadata
 *
 * @param options - Validation options containing the credential offer, config, and optional metadata
 * @returns Resolves when the credential offer satisfies IT-Wallet validation rules.
 * @throws {CredentialOfferError} If any validation rule fails
 * @throws {ItWalletSpecsVersionError} If the configured version does not support credential offers
 */
export async function validateCredentialOffer(
  options: ValidateCredentialOfferOptions,
): Promise<void> {
  return dispatchValidateCredentialOffer(options);
}
