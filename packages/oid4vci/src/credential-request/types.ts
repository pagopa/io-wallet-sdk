import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import type { CredentialRequestV1_0 } from "./v1.0/z-credential";
import type { CredentialRequestV1_3 } from "./v1.3/z-credential";

/**
 * Base options shared across all credential request versions
 */
export interface BaseCredentialRequestOptions {
  callbacks: Pick<CallbackContext, "signJwt">;
  clientId: string;
  credential_identifier: string;
  issuerIdentifier: string;
  nonce: string;
  signer: JwtSignerJwk;
}

/**
 * Options for creating a credential request with v1.0.2
 * Does NOT include keyAttestation parameter
 */
export interface CredentialRequestOptionsV1_0
  extends BaseCredentialRequestOptions {
  config: {
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0;
  } & IoWalletSdkConfig;
  // keyAttestation is NOT accepted in v1.0.2
}

/**
 * Options for creating a credential request with v1.3.3
 * Requires keyAttestation parameter
 */
export interface CredentialRequestOptionsV1_3
  extends BaseCredentialRequestOptions {
  config: {
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3;
  } & IoWalletSdkConfig;
  keyAttestation: string; // Required in v1.3.3
}

/**
 * Union type for credential request options
 * Used by the version router
 */
export type CredentialRequestOptions =
  | CredentialRequestOptionsV1_0
  | CredentialRequestOptionsV1_3;

/**
 * Union type for credential request return values
 * TypeScript will narrow this based on the config version
 */
export type CredentialRequest = CredentialRequestV1_0 | CredentialRequestV1_3;
