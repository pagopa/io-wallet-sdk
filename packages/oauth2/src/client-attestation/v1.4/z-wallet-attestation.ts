import {
  zCertificateChain,
  zJwk,
  zJwtHeader,
  zJwtPayload,
  zTrustChain,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

export const zWalletAttestationJwtHeaderV1_4 = z.looseObject({
  ...zJwtHeader.shape,
  kid: z.string(),
  trust_chain: zTrustChain.optional(),
  typ: z.literal("oauth-client-attestation+jwt"),
  x5c: zCertificateChain,
});

/**
 * The maximum validity period of a Wallet Instance Attestation after issuance.
 * The v1.4 specification sets an upper limit of 24 hours.
 *
 * See {@link https://italia.github.io/eid-wallet-it-docs/releases/1.4.7/en/wallet-solution-requirements.html}
 */
export const MAX_WALLET_ATTESTATION_TTL_SECONDS = 86400; // 24 hours

export const zWalletAttestationJwtPayloadV1_4 = z
  .looseObject({
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
  })
  .refine(
    (payload) => payload.exp - payload.iat < MAX_WALLET_ATTESTATION_TTL_SECONDS,
    {
      message: "exp - iat must be strictly less than 24 hours",
      path: ["exp"],
    },
  );

export type WalletAttestationJwtV1_4 = string;

export const zWalletAttestationJwtV1_4 = z.string().min(1);
