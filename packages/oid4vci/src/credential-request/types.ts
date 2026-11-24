import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import type { CredentialRequestOptionsV1_0 } from "./v1.0/create-credential-request";
import type { CredentialRequestV1_0 } from "./v1.0/z-credential";
import type { CredentialRequestOptionsV1_3 } from "./v1.3/create-credential-request";
import type { CredentialRequestV1_3 } from "./v1.3/z-credential";

// Re-export version-specific options
export type { CredentialRequestOptionsV1_0, CredentialRequestOptionsV1_3 };

/**
 * Base options shared across all credential request versions
 */
export interface BaseCredentialRequestOptions {
  clientId: string;
  credential_identifier: string;
  issuerIdentifier: string;
  nonce: string;
}

export type CredentialRequestOptionsV1_4 = {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
} & Omit<CredentialRequestOptionsV1_3, "config">;

/**
 * Union type for credential request options
 * Used by the version router
 */
export type CredentialRequestOptions =
  | CredentialRequestOptionsV1_0
  | CredentialRequestOptionsV1_3
  | CredentialRequestOptionsV1_4;

/**
 * Union type for credential request return values
 * TypeScript will narrow this based on the config version
 */
export type CredentialRequest = CredentialRequestV1_0 | CredentialRequestV1_3;
