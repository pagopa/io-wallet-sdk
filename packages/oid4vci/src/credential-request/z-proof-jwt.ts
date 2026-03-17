import { zJwk } from "@pagopa/io-wallet-oauth2";
import { z } from "zod";

const zBaseProofJwtHeader = z.object({
  alg: z.string().min(1),
  jwk: zJwk,
  typ: z.literal("openid4vci-proof+jwt"),
});

export const zProofJwtHeaderV1_0 = zBaseProofJwtHeader.loose();

export const zProofJwtHeaderV1_3 = zBaseProofJwtHeader
  .extend({
    key_attestation: z.string().min(1),
  })
  .loose();

export const zProofJwtPayload = z.looseObject({
  aud: z.string().min(1),
  iat: z.number(),
  iss: z.string().min(1).optional(),
  nonce: z.string().min(1),
});

export type ProofJwtHeaderV1_0 = z.infer<typeof zProofJwtHeaderV1_0>;
export type ProofJwtHeaderV1_3 = z.infer<typeof zProofJwtHeaderV1_3>;
export type ProofJwtHeader = ProofJwtHeaderV1_0 | ProofJwtHeaderV1_3;
export type ProofJwtPayload = z.infer<typeof zProofJwtPayload>;
