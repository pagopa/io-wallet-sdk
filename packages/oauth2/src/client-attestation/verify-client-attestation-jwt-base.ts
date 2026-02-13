import { decodeJwt, jwtSignerFromJwt, verifyJwt } from "@openid4vc/oauth2";
import { ZodType, z } from "zod";

import { BaseVerifyClientAttestationJwtOptions } from "./types";

export async function verifyClientAttestationJwtBase<
  THeader extends ZodType,
  TPayload extends ZodType,
>(
  options: BaseVerifyClientAttestationJwtOptions,
  headerSchema: THeader,
  payloadSchema: TPayload,
): Promise<{
  header: z.infer<THeader>;
  payload: z.infer<TPayload>;
  signer: Awaited<ReturnType<typeof verifyJwt>>["signer"];
}> {
  const { header, payload } = decodeJwt({
    headerSchema,
    jwt: options.clientAttestationJwt,
    payloadSchema,
  });

  const { signer } = await verifyJwt({
    compact: options.clientAttestationJwt,
    errorMessage: "client attestation jwt verification failed.",
    header,
    now: options.now,
    payload,
    signer: jwtSignerFromJwt({ header, payload }),
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  return { header, payload, signer };
}
