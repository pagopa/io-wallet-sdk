import type {
  WalletAttestationOptionsV1_0,
  WalletAttestationOptionsV1_3,
  WalletAttestationOptionsV1_4,
} from "@pagopa/io-wallet-oauth2";

export type { BaseWalletAttestationOptions } from "@pagopa/io-wallet-oauth2";

/**
 * Union type for wallet attestation options
 * Used by the version router
 */
export type WalletAttestationOptions =
  | WalletAttestationOptionsV1_0
  | WalletAttestationOptionsV1_3
  | WalletAttestationOptionsV1_4;
