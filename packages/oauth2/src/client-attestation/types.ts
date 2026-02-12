import {
  CallbackContext,
  ClientAttestationJwtPayload,
} from "@openid4vc/oauth2";
import { IoWalletSdkConfig } from "@pagopa/io-wallet-utils";

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
