import {
  ValidationError,
  addSecondsToDate,
  dateToSeconds,
} from "@pagopa/io-wallet-utils";

import { decodeJwt } from "../../common/jwt/decode-jwt";
import { ClientAttestationError } from "../../errors";
import { calculateDpopJwkThumbprint } from "../jwk-thumbprint";
import { BaseWalletAttestationOptions } from "../types";
import {
  WalletAttestationJwtV1_4,
  zWalletAttestationJwtHeaderV1_4,
  zWalletAttestationJwtPayloadV1_4,
} from "./z-wallet-attestation";

const DEFAULT_EXPIRATION_SECONDS = 3600;

const MAX_EXPIRATION_SECONDS = 86400;

export interface WalletAttestationOptionsV1_4 extends Omit<
  BaseWalletAttestationOptions,
  "walletLink" | "walletName"
> {
  nbf?: Date;
  signer: {
    alg: string;
    kid: string;
    method: "x5c";
    trustChain?: [string, ...string[]];
    x5c: [string, ...string[]];
  };
  walletLink: string;
  walletName: string;
}

/**
 * Creates a wallet attestation JWT for IT-Wallet v1.4.
 *
 * @param options - v1.4 wallet attestation creation options.
 * @returns Signed wallet attestation JWT.
 * @throws {ValidationError} If temporal constraints or generated JWT validation fail.
 * @throws {ClientAttestationError} For unexpected errors during attestation creation.
 */
export const createWalletAttestationJwt = async (
  options: WalletAttestationOptionsV1_4,
): Promise<WalletAttestationJwtV1_4> => {
  try {
    const { signJwt } = options.callbacks;
    const iat = new Date();
    const exp =
      options.expiresAt ?? addSecondsToDate(iat, DEFAULT_EXPIRATION_SECONDS);

    if (exp <= iat) {
      throw new ValidationError("exp must be after iat");
    }

    if (exp > addSecondsToDate(iat, MAX_EXPIRATION_SECONDS)) {
      throw new ValidationError("exp must not be more than 24 hours after iat");
    }

    if (options.nbf && options.nbf >= exp) {
      throw new ValidationError("nbf must be before exp");
    }

    const dpopJwkThumbprint = await calculateDpopJwkThumbprint(options);

    const payload = {
      cnf: { jwk: options.dpopJwkPublic },
      exp: dateToSeconds(exp),
      iat: dateToSeconds(iat),
      iss: options.issuer,
      sub: dpopJwkThumbprint,
      wallet_link: options.walletLink,
      wallet_name: options.walletName,
      ...(options.nbf && { nbf: dateToSeconds(options.nbf) }),
    };

    const header = {
      alg: options.signer.alg,
      kid: options.signer.kid,
      typ: "oauth-client-attestation+jwt",
      x5c: options.signer.x5c,
      ...(options.signer.trustChain && {
        trust_chain: options.signer.trustChain,
      }),
    };

    const result = await signJwt(options.signer, {
      header,
      payload,
    });

    decodeJwt({
      errorMessagePrefix: "Error decoding wallet attestation JWT:",
      headerSchema: zWalletAttestationJwtHeaderV1_4,
      jwt: result.jwt,
      payloadSchema: zWalletAttestationJwtPayloadV1_4,
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
