import {
  CallbackContext,
  ClientAttestationJwtPayload,
} from "@openid4vc/oauth2";
import { IoWalletSdkConfig } from "@pagopa/io-wallet-utils";

import type { WalletAttestationOptionsV1_0 } from "./v1.0";
import type { WalletAttestationOptionsV1_3 } from "./v1.3";

// Re-export version-specific options
export type { WalletAttestationOptionsV1_0, WalletAttestationOptionsV1_3 };

/**
 * Base options shared across all wallet attestation versions
 */
export interface BaseWalletAttestationOptions {
  callbacks: Pick<CallbackContext, "signJwt">;
  config: IoWalletSdkConfig;
  dpopJwkPublic: ClientAttestationJwtPayload["cnf"]["jwk"];
  expiresAt?: Date;
  issuer: string;
  walletLink?: string;
  walletName?: string;
}

/**
 * Union type for wallet attestation options
 * Used by the version router
 */
export type WalletAttestationOptions =
  | WalletAttestationOptionsV1_0
  | WalletAttestationOptionsV1_3;
