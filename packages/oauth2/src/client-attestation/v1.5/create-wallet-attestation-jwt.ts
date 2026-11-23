import {
  type CallbackContext,
  ValidationError,
  addSecondsToDate,
  dateToSeconds,
  decodeJwt,
} from "@pagopa/io-wallet-utils";

import { ClientAttestationError } from "../../errors";
import { BaseWalletAttestationOptions } from "../types";
import {
  WalletAttestationJwtV1_5,
  zWalletAttestationJwtHeaderV1_5,
  zWalletAttestationJwtPayloadV1_5,
} from "./z-wallet-attestation";

const DEFAULT_EXPIRATION_SECONDS = 3600;

const MAX_EXPIRATION_SECONDS = 86400;

export interface WalletAttestationOptionsV1_5 extends Omit<
  BaseWalletAttestationOptions,
  "callbacks" | "issuer" | "walletLink" | "walletName"
> {
  callbacks: Pick<CallbackContext, "signJwt">;
  clientStatus: {
    expiresAt: Date;
    statusList: { idx: number; uri: string };
  };
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
  walletSolutionCertificationInformation?: string;
  walletSolutionId: string;
  walletVersion: string;
}

/**
 * Creates a wallet attestation JWT for IT-Wallet v1.5.
 *
 * @param options - v1.5 wallet attestation creation options.
 * @returns Signed wallet attestation JWT.
 * @throws {ValidationError} If temporal constraints or generated JWT validation fail.
 * @throws {ClientAttestationError} For unexpected errors during attestation creation.
 */
export const createWalletAttestationJwt = async (
  options: WalletAttestationOptionsV1_5,
): Promise<WalletAttestationJwtV1_5> => {
  try {
    const { signJwt } = options.callbacks;
    const now = new Date();
    const exp =
      options.expiresAt ?? addSecondsToDate(now, DEFAULT_EXPIRATION_SECONDS);

    if (exp <= now) {
      throw new ValidationError("exp must be in the future");
    }

    if (exp > addSecondsToDate(now, MAX_EXPIRATION_SECONDS)) {
      throw new ValidationError("exp must not be more than 24 hours from now");
    }

    if (options.nbf && options.nbf >= exp) {
      throw new ValidationError("nbf must be before exp");
    }

    const payload = {
      client_status: {
        exp: dateToSeconds(options.clientStatus.expiresAt),
        status: { status_list: options.clientStatus.statusList },
      },
      cnf: { jwk: options.dpopJwkPublic },
      exp: dateToSeconds(exp),
      sub: options.walletSolutionId,
      wallet_link: options.walletLink,
      wallet_name: options.walletName,
      wallet_version: options.walletVersion,
      ...(options.nbf && { nbf: dateToSeconds(options.nbf) }),
      ...(options.walletSolutionCertificationInformation && {
        wallet_solution_certification_information:
          options.walletSolutionCertificationInformation,
      }),
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
      headerSchema: zWalletAttestationJwtHeaderV1_5,
      jwt: result.jwt,
      payloadSchema: zWalletAttestationJwtPayloadV1_5,
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
