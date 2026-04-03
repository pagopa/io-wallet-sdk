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
    errorMessagePrefix: "Error decoding wallet attestation JWT:",
    headerSchema,
    jwt: options.walletAttestationJwt,
    payloadSchema,
  });

  const { signer } = await verifyJwt({
    compact: options.walletAttestationJwt,
    errorMessage: "wallet attestation verification failed.",
    header,
    now: options.now,
    payload,
    signer: jwtSignerFromJwt({ header, payload }),
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  return { header, payload, signer };
}
