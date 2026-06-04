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
 * Validations shared across all IT-Wallet credential offer versions.
 *
 * @throws {CredentialOfferError} If any shared validation rule fails.
 */
function validateBaseCredentialOffer(options: {
  credentialIssuerMetadata?: { authorization_servers?: string[] };
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
    if (
      authCodeGrant.authorization_server &&
      !authServers.includes(authCodeGrant.authorization_server)
    ) {
      throw new CredentialOfferError(
        `authorization_server '${authCodeGrant.authorization_server}' does not match Credential Issuer metadata. Valid servers: ${authServers.join(", ")}`,
      );
    }
  }
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
