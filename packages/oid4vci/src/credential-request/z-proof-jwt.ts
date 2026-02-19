import { z } from "zod";

export const zProofJwtHeader = z
  .object({
    alg: z.string().nonempty(),
    typ: z.literal("openid4vci-proof+jwt"),
  })
  .passthrough();

export const zProofJwtPayload = z
  .object({
    aud: z.string().min(1),
    iat: z.number(),
    iss: z.string().min(1).optional(),
    nonce: z.string().min(1),
  })
  .passthrough();

export type ProofJwtHeader = z.infer<typeof zProofJwtHeader>;
export type ProofJwtPayload = z.infer<typeof zProofJwtPayload>;
