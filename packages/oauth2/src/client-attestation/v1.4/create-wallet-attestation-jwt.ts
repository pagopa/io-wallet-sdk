import {
  ValidationError,
  addSecondsToDate,
  dateToSeconds,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

import { decodeJwt } from "../../common/jwt/decode-jwt";
import { ClientAttestationError } from "../../errors";
import { BaseWalletAttestationOptions } from "../types";
import {
  WalletAttestationJwtV1_4,
  zEudiWalletInfoV1_4,
  zWalletAttestationJwtHeaderV1_4,
  zWalletAttestationJwtPayloadV1_4,
  zWalletAttestationStatusV1_4,
} from "./z-wallet-attestation";

export interface WalletAttestationOptionsV1_4
  extends Omit<BaseWalletAttestationOptions, "walletLink" | "walletName"> {
  eudiWalletInfo?: z.infer<typeof zEudiWalletInfoV1_4>;
  signer: {
    alg: string;
    kid: string;
    method: "x5c";
    trustChain?: [string, ...string[]];
    x5c: [string, ...string[]];
  };
  status: z.infer<typeof zWalletAttestationStatusV1_4>;
  walletLink: string;
  walletName: string;
}

export const createWalletAttestationJwt = async (
  options: WalletAttestationOptionsV1_4,
): Promise<WalletAttestationJwtV1_4> => {
  try {
    const { signJwt } = options.callbacks;
    const exp =
      options.expiresAt ?? addSecondsToDate(new Date(), 3600 * 24 * 60);

    const payload = parseWithErrorHandling(
      zWalletAttestationJwtPayloadV1_4,
      {
        cnf: { jwk: options.dpopJwkPublic },
        exp: dateToSeconds(exp),
        iat: dateToSeconds(new Date()),
        iss: options.issuer,
        status: options.status,
        sub: options.dpopJwkPublic.kid,
        wallet_link: options.walletLink,
        wallet_name: options.walletName,
        ...(options.eudiWalletInfo && {
          eudi_wallet_info: options.eudiWalletInfo,
        }),
      },
      "Invalid v1.4 wallet attestation payload",
    );

    const header = parseWithErrorHandling(
      zWalletAttestationJwtHeaderV1_4,
      {
        alg: options.signer.alg,
        kid: options.signer.kid,
        typ: "oauth-client-attestation+jwt",
        x5c: options.signer.x5c,
        ...(options.signer.trustChain && {
          trust_chain: options.signer.trustChain,
        }),
      },
      "Invalid v1.4 wallet attestation header",
    );

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
