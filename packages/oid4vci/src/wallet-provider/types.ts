import type { V1_0, V1_3 } from "@pagopa/io-wallet-oauth2";

export type { BaseWalletAttestationOptions } from "@pagopa/io-wallet-oauth2";

export type WalletAttestationOptionsV1_0 = V1_0.WalletAttestationOptionsV1_0;
export type WalletAttestationOptionsV1_3 = V1_3.WalletAttestationOptionsV1_3;

/**
 * Union type for wallet attestation options
 * Used by the version router
 */
export type WalletAttestationOptions =
  | WalletAttestationOptionsV1_0
  | WalletAttestationOptionsV1_3;
