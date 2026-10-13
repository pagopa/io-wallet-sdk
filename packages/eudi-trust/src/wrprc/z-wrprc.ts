import { z } from "zod";

/**
 * Minimal WRPRC JWT header (ETSI TS 119 475 clause 5.2.1): only the parameters
 * needed for its validation are checked.
 */
export type WRPRCJwtHeader = z.infer<typeof zWRPRCJwtHeader>;
export const zWRPRCJwtHeader = z.looseObject({
  alg: z.string(),
  typ: z.literal("rc-wrp+jwt"),
  x5c: z.tuple([z.string()], z.string()),
});

/** Minimal WRPRC JWT payload: only the claims needed for its validation are checked. */
export type WRPRCPayload = z.infer<typeof zWRPRCPayload>;
export const zWRPRCPayload = z.looseObject({
  exp: z.number().int().optional(),
  iat: z.number().int().optional(),
});
