import {
  MAX_JTI_LENGTH,
  zHttpMethod,
  zJwk,
  zJwtHeader,
  zJwtPayload,
} from "@pagopa/io-wallet-utils";
import z from "zod";

export const zDpopJwtPayload = z.looseObject({
  ...zJwtPayload.shape,
  ath: z.optional(z.string()),
  htm: zHttpMethod,
  htu: z.url(),
  iat: z.number().int().nonnegative(),
  jti: z.string().max(MAX_JTI_LENGTH),
  nonce: z.optional(z.string()),
});

export type DpopJwtPayload = z.infer<typeof zDpopJwtPayload>;

export const zDpopJwtHeader = z.looseObject({
  ...zJwtHeader.shape,
  jwk: zJwk,
  typ: z.literal("dpop+jwt"),
});

export type DpopJwtHeader = z.infer<typeof zDpopJwtHeader>;

/**
 * Error response of a server requiring a DPoP nonce (RFC 9449, Section 8).
 */
export const zDpopNonceErrorResponse = z.looseObject({
  error: z.literal("use_dpop_nonce"),
});

export type DpopNonceErrorResponse = z.infer<typeof zDpopNonceErrorResponse>;
