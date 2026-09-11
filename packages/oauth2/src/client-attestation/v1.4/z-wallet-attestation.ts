import { z } from "zod";

import { zJwk } from "../../common/jwk/z-jwk";
import { zJwtHeader, zJwtPayload } from "../../common/jwt/z-jwt";
import { zCertificateChain, zTrustChain } from "../../common/z-common";

export const zWalletAttestationJwtHeaderV1_4 = z.looseObject({
  ...zJwtHeader.shape,
  kid: z.string(),
  trust_chain: zTrustChain.optional(),
  typ: z.literal("oauth-client-attestation+jwt"),
  x5c: zCertificateChain,
});

export const zWalletAttestationJwtPayloadV1_4 = z.looseObject({
  ...zJwtPayload.shape,
  cnf: z.object({
    jwk: zJwk,
  }),
  exp: z.number().int(),
  iat: z.number().int(),
  iss: z.string(),
  nbf: z.number().optional(),
  sub: z.string(),
  wallet_link: z.url(),
  wallet_name: z.string(),
});

export type WalletAttestationJwtV1_4 = string;

export const zWalletAttestationJwtV1_4 = z.string().min(1);
