import { decodeJwt, jwtSignerFromJwt, verifyJwt } from "@openid4vc/oauth2";
import { ZodType, z } from "zod";

import { BaseVerifyWalletAttestationJwtOptions } from "./types";

export async function verifyWalletAttestationBase<
  THeader extends ZodType,
  TPayload extends ZodType,
>(
  options: BaseVerifyWalletAttestationJwtOptions,
  headerSchema: THeader,
  payloadSchema: TPayload,
): Promise<{
  header: z.infer<THeader>;
  payload: z.infer<TPayload>;
  signer: Awaited<ReturnType<typeof verifyJwt>>["signer"];
}> {
  const { header, payload } = decodeJwt({
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
