import { zJwk, zJwtHeader, zJwtPayload } from "@openid4vc/oauth2";
import { zHttpMethod, zHttpsUrl, zInteger } from "@openid4vc/utils";
import z from "zod";

export const zDpopJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    ath: z.optional(z.string()),
    htm: zHttpMethod,
    htu: zHttpsUrl,
    iat: zInteger,

    jti: z.string(),
  })
  .passthrough();
export type DpopJwtPayload = z.infer<typeof zDpopJwtPayload>;

export const zDpopJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    jwk: zJwk,
    typ: z.literal("dpop+jwt"),
  })
  .passthrough();
export type DpopJwtHeader = z.infer<typeof zDpopJwtHeader>;
