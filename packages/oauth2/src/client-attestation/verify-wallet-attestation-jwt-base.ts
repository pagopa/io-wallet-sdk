import type { ZodType } from "zod";

import { jwtSignerFromJwt, verifyJwt } from "@openid4vc/oauth2";

import type { JwtHeader, JwtPayload } from "../common/jwt/z-jwt";
import type { BaseVerifyWalletAttestationJwtOptions } from "./types";

import { decodeJwt } from "../common/jwt/decode-jwt";

export async function verifyWalletAttestationBase<
  THeader extends ZodType<JwtHeader>,
  TPayload extends ZodType<JwtPayload>,
>(
  options: BaseVerifyWalletAttestationJwtOptions,
  headerSchema: THeader,
  payloadSchema: TPayload,
) {
  const { header, payload } = decodeJwt({
    headerSchema,
    jwt: options.walletAttestationJwt,
    payloadSchema,
  });

  const jwtHeader: JwtHeader = header;
  const jwtPayload: JwtPayload = payload;

  const { signer } = await verifyJwt({
    compact: options.walletAttestationJwt,
    errorMessage: "wallet attestation verification failed.",
    header: jwtHeader,
    now: options.now,
    payload: jwtPayload,
    signer: jwtSignerFromJwt({ header: jwtHeader, payload: jwtPayload }),
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  return { header, payload, signer };
}
