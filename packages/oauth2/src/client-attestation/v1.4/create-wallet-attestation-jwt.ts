import {
  ValidationError,
  addSecondsToDate,
  dateToSeconds,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

import { decodeJwt } from "../../common/jwt/decode-jwt";
import { ClientAttestationError } from "../../errors";
import { calculateDpopJwkThumbprint } from "../jwk-thumbprint";
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
  nbf?: Date;
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
    const iat = new Date();
    const exp = options.expiresAt ?? addSecondsToDate(iat, 3600); // Default expiration of 1 hour

    // Validate temporal constraints
    if (options.nbf && options.nbf >= exp) {
      throw new ValidationError("nbf must be before exp");
    }

    const dpopJwkThumbprint = await calculateDpopJwkThumbprint(options);

    const payload = {
      cnf: { jwk: options.dpopJwkPublic },
      exp: dateToSeconds(exp),
      iat: dateToSeconds(iat),
      iss: options.issuer,
      status: options.status,
      sub: dpopJwkThumbprint,
      wallet_link: options.walletLink,
      wallet_name: options.walletName,
      ...(options.nbf && { nbf: dateToSeconds(options.nbf) }),
      ...(options.eudiWalletInfo && {
        eudi_wallet_info: options.eudiWalletInfo,
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
