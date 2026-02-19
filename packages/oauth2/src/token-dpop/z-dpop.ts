import { zHttpMethod } from "@pagopa/io-wallet-utils";
import z from "zod";

import { zJwk } from "../common/jwk/z-jwk";
import { zJwtHeader, zJwtPayload } from "../common/jwt/z-jwt";

export const zDpopJwtPayload = z
  .object({
    ...zJwtPayload.shape,
    ath: z.optional(z.string()),
    htm: zHttpMethod,
    htu: z.string().url(),
    iat: z.number().int().nonnegative(),

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
