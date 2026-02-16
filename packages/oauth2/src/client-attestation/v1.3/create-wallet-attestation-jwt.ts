import { decodeJwt } from "@openid4vc/oauth2";
import {
  ValidationError,
  addSecondsToDate,
  dateToSeconds,
} from "@openid4vc/utils";

import { ClientAttestationError } from "../../errors";
import { BaseWalletAttestationOptions } from "../types";
import {
  WalletAttestationJwtV1_3,
  zWalletAttestationJwtHeaderV1_3,
  zWalletAttestationJwtPayloadV1_3,
} from "./z-wallet-attestation";

/**
 * Options for creating a wallet attestation with v1.3
 * Requires x5c, optional trust_chain, nbf, and status
 */
export interface WalletAttestationOptionsV1_3
  extends BaseWalletAttestationOptions {
  // NEW OPTIONAL CLAIMS
  nbf?: Date; // Not Before timestamp

  signer: {
    alg: string;
    kid: string;
    method: "x5c";
    trustChain?: [string, ...string[]]; // OPTIONAL in v1.3
    x5c: [string, ...string[]]; // REQUIRED in v1.3
  };
  status?: {
    status_list: {
      idx: number;
      uri: string;
    };
  }; // Status object for revocation mechanisms
}

/**
 * Create a Wallet Attestation JWT for IT-Wallet v1.3
 *
 * Version 1.3 specifics:
 * - x5c in header is REQUIRED
 * - trust_chain in header is OPTIONAL
 * - Supports nbf and status claims in payload
 *
 * @param options - Wallet attestation options for v1.3
 * @returns Signed wallet attestation JWT string
 * @throws {ValidationError} When validation fails (including nbf >= exp)
 * @throws {ClientAttestationError} For other unexpected errors during creation
 * @internal This function is called by the WalletProvider router
 */
export const createWalletAttestationJwt = async (
  options: WalletAttestationOptionsV1_3,
): Promise<WalletAttestationJwtV1_3> => {
  try {
    const { signJwt } = options.callbacks;

    // Calculate default expiration (60 days)
    const exp =
      options.expiresAt ?? addSecondsToDate(new Date(), 3600 * 24 * 60);

    // Validate temporal constraints
    if (options.nbf && options.nbf >= exp) {
      throw new ValidationError("nbf must be before exp");
    }

    const payload = {
      cnf: { jwk: options.dpopJwkPublic },
      exp: dateToSeconds(exp),
      iat: dateToSeconds(new Date()),
      iss: options.issuer,
      sub: options.dpopJwkPublic.kid,
      ...(options.nbf && { nbf: dateToSeconds(options.nbf) }),
      ...(options.status && { status: options.status }),
      ...(options.walletLink && { wallet_link: options.walletLink }),
      ...(options.walletName && { wallet_name: options.walletName }),
    };

    const header = {
      alg: options.signer.alg,
      kid: options.signer.kid,
      typ: "oauth-client-attestation+jwt",
      x5c: options.signer.x5c, // REQUIRED
      ...(options.signer.trustChain && {
        trust_chain: options.signer.trustChain,
      }),
    };

    const result = await signJwt(options.signer, {
      header,
      payload,
    });

    // Validate the generated JWT structure
    decodeJwt({
      headerSchema: zWalletAttestationJwtHeaderV1_3,
      jwt: result.jwt,
      payloadSchema: zWalletAttestationJwtPayloadV1_3,
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
