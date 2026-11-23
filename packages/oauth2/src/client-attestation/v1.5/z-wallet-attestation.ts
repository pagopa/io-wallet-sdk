import {
  zCertificateChain,
  zJwk,
  zJwtHeader,
  zJwtPayload,
  zTrustChain,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

export const zWalletAttestationJwtHeaderV1_5 = z.looseObject({
  ...zJwtHeader.shape,
  kid: z.string(),
  trust_chain: zTrustChain.optional(),
  typ: z.literal("oauth-client-attestation+jwt"),
  x5c: zCertificateChain,
});

export const zWalletAttestationJwtPayloadV1_5 = z.looseObject({
  ...zJwtPayload.shape,
  client_status: z.object({
    exp: z.number().int(),
    status: z.object({
      status_list: z.object({
        idx: z.number().int().nonnegative(),
        uri: z.url(),
      }),
    }),
  }),
  cnf: z.object({
    jwk: zJwk,
  }),
  exp: z.number().int(),
  nbf: z.number().optional(),
  sub: z.url(),
  wallet_link: z.url(),
  wallet_name: z.string(),
  wallet_solution_certification_information: z.url().optional(),
  wallet_version: z.string(),
});

export type WalletAttestationJwtV1_5 = string;

export const zWalletAttestationJwtV1_5 = z.string().min(1);
