import { z } from "zod";

import { zJwk } from "../../common/jwk/z-jwk";
import { zJwtHeader, zJwtPayload } from "../../common/jwt/z-jwt";
import { zCertificateChain, zTrustChain } from "../../common/z-common";

export const zWalletAttestationStatusV1_4 = z.object({
  status_list: z.object({
    idx: z.number().int(),
    uri: z.string(),
  }),
});

export const zEudiWalletInfoV1_4 = z.object({
  general_info: z.object({
    wallet_provider_name: z.string(),
    wallet_solution_certification_information: z.string(),
    wallet_solution_id: z.string(),
    wallet_solution_version: z.string(),
  }),
});

export const zWalletAttestationJwtHeaderV1_4 = z.looseObject({
  ...zJwtHeader.shape,
  trust_chain: zTrustChain.optional(),
  typ: z.literal("oauth-client-attestation+jwt"),
  x5c: zCertificateChain,
});

export const zWalletAttestationJwtPayloadV1_4 = z.looseObject({
  ...zJwtPayload.shape,
  cnf: z.object({
    jwk: zJwk,
  }),
  eudi_wallet_info: zEudiWalletInfoV1_4.optional(),
  exp: z.number().int(),
  iat: z.number().int(),
  iss: z.string(),
  nbf: z.number().optional(),
  status: zWalletAttestationStatusV1_4,
  sub: z.string(),
  wallet_link: z.url(),
  wallet_name: z.string(),
});

export type WalletAttestationJwtV1_4 = string;

export const zWalletAttestationJwtV1_4 = z.string().min(1);
