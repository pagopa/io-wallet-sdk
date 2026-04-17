import { zHttpMethod } from "@pagopa/io-wallet-utils";
import z from "zod";

import { zJwk } from "../common/jwk/z-jwk";
import { MAX_JTI_LENGTH, zJwtHeader, zJwtPayload } from "../common/jwt/z-jwt";

export const zDpopJwtPayload = z.looseObject({
  ...zJwtPayload.shape,
  ath: z.optional(z.string()),
  htm: zHttpMethod,
  htu: z.url(),
  iat: z.number().int().nonnegative(),
  jti: z.string().max(MAX_JTI_LENGTH),
});

export type DpopJwtPayload = z.infer<typeof zDpopJwtPayload>;

export const zDpopJwtHeader = z.looseObject({
  ...zJwtHeader.shape,
  jwk: zJwk,
  typ: z.literal("dpop+jwt"),
});

export type DpopJwtHeader = z.infer<typeof zDpopJwtHeader>;
