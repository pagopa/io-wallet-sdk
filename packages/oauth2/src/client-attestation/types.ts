import {
  CallbackContext,
  ClientAttestationJwtPayload,
} from "@openid4vc/oauth2";
import { IoWalletSdkConfig } from "@pagopa/io-wallet-utils";
import z from "zod";

export interface BaseVerifyWalletAttestationJwtOptions {
  callbacks: Pick<CallbackContext, "verifyJwt">;
  now?: Date;
  walletAttestationJwt: string;
}

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

export const zOauthClientAttestationHeader = z.literal(
  "OAuth-Client-Attestation",
);

export const oauthClientAttestationHeader = zOauthClientAttestationHeader.value;

export const zOauthClientAttestationPopHeader = z.literal(
  "OAuth-Client-Attestation-PoP",
);

export const oauthClientAttestationPopHeader =
  zOauthClientAttestationPopHeader.value;
