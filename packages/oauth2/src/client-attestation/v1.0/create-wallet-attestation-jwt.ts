import {
  ValidationError,
  addSecondsToDate,
  dateToSeconds,
} from "@pagopa/io-wallet-utils";

import { decodeJwt } from "../../common/jwt/decode-jwt";
import { ClientAttestationError } from "../../errors";
import { BaseWalletAttestationOptions } from "../types";
import {
  WalletAttestationJwtV1_0,
  zWalletAttestationJwtHeaderV1_0,
  zWalletAttestationJwtPayloadV1_0,
} from "./z-wallet-attestation";

/**
 * Options for creating a wallet attestation with v1.0
 * Uses only trust_chain (federation method)
 */
export interface WalletAttestationOptionsV1_0
  extends BaseWalletAttestationOptions {
  /**
   * It expresses the strength of the authentication mechanism backing the Wallet instance when interacting with a Relying Party.
   */
  authenticatorAssuranceLevel: string;

  signer: {
    alg: string;
    kid: string;
    method: "federation";
    trustChain: [string, ...string[]]; // REQUIRED in v1.0
  };
}

/**
 * Create a Wallet Attestation JWT for IT-Wallet v1.0
 *
 * Version 1.0 specifics:
 * - Uses only `trust_chain` in header (federation method)
 *
 * @param options - Wallet attestation options for v1.0
 * @returns Signed wallet attestation JWT string
 * @throws {ValidationError} When validation of the JWT structure fails
 * @throws {ClientAttestationError} For other unexpected errors during creation
 * @internal This function is called by the WalletProvider router
 */
export const createWalletAttestationJwt = async (
  options: WalletAttestationOptionsV1_0,
): Promise<WalletAttestationJwtV1_0> => {
  try {
    const { signJwt } = options.callbacks;
    // Calculate default expiration (60 days)
    const exp =
      options.expiresAt ?? addSecondsToDate(new Date(), 3600 * 24 * 60);

    const payload = {
      cnf: { jwk: options.dpopJwkPublic },
      exp: dateToSeconds(exp),
      iat: dateToSeconds(new Date()),
      iss: options.issuer,
      sub: options.dpopJwkPublic.kid,
      ...(options.walletLink && { wallet_link: options.walletLink }),
      ...(options.walletName && { wallet_name: options.walletName }),
      aal: options.authenticatorAssuranceLevel,
    };

    const header = {
      alg: options.signer.alg,
      kid: options.signer.kid,
      trust_chain: options.signer.trustChain,
      typ: "oauth-client-attestation+jwt",
    };

    const result = await signJwt(options.signer, {
      header,
      payload,
    });

    decodeJwt({
      headerSchema: zWalletAttestationJwtHeaderV1_0,
      jwt: result.jwt,
      payloadSchema: zWalletAttestationJwtPayloadV1_0,
    });

    return result.jwt;
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    throw new ClientAttestationError(
      `Unexpected error during wallet attestation creation: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
};
