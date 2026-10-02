import type { ZodType } from "zod";

import {
  type JwtHeader,
  type JwtPayload,
  decodeJwt,
  jwtSignerFromJwt,
  verifyJwt,
} from "@pagopa/io-wallet-utils";

import type { BaseVerifyWalletAttestationJwtOptions } from "./types";

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
