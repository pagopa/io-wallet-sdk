import z from "zod";

import { MAX_JTI_LENGTH, zJwtHeader, zJwtPayload } from "../common/jwt/z-jwt";

export const IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES = [
  "ES256",
  "ES384",
  "ES512",
] as const;

export const zItWalletClientAttestationPopJwtAlg = z.enum(
  IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES,
);

export type ItWalletClientAttestationPopJwtAlg = z.infer<
  typeof zItWalletClientAttestationPopJwtAlg
>;

export const zItWalletClientAttestationPopJwtPayload = z.looseObject({
  ...zJwtPayload.shape,
  aud: z.string(),
  exp: z.number().int().optional(),
  iat: z.number().int(),
  iss: z.string(),
  jti: z.string().max(MAX_JTI_LENGTH),
  nonce: z.string().optional(),
});

export type ItWalletClientAttestationPopJwtPayload = z.infer<
  typeof zItWalletClientAttestationPopJwtPayload
>;

export const zItWalletClientAttestationPopJwtTyp = z.literal(
  "oauth-client-attestation-pop+jwt",
);

export const zItWalletClientAttestationPopJwtHeader = z.looseObject({
  ...zJwtHeader.shape,
  typ: zItWalletClientAttestationPopJwtTyp,
});

export type ItWalletClientAttestationPopJwtHeader = z.infer<
  typeof zItWalletClientAttestationPopJwtHeader
>;
