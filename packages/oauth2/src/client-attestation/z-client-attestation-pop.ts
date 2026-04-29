import z from "zod";

import { MAX_JTI_LENGTH, zJwtHeader, zJwtPayload } from "../common/jwt/z-jwt";

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
