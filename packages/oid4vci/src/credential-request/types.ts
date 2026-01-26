import { CallbackContext, JwtSignerJwk } from "@openid4vc/oauth2";

import type { CredentialRequestOptionsV1_0 } from "./v1.0";
import type { CredentialRequestV1_0 } from "./v1.0/z-credential";
import type { CredentialRequestOptionsV1_3 } from "./v1.3";
import type { CredentialRequestV1_3 } from "./v1.3/z-credential";

// Re-export version-specific options
export type { CredentialRequestOptionsV1_0, CredentialRequestOptionsV1_3 };

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
