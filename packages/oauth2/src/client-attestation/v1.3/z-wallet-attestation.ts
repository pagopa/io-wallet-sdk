import { zJwk, zJwtHeader, zJwtPayload } from "@openid4vc/oauth2";
import { z } from "zod";

/**
 * JWT Header schema for IT-Wallet v1.3 Wallet Attestation
 *
 * Version 1.3 specifics:
 * - x5c is REQUIRED
 * - trust_chain is OPTIONAL
 */
export const zWalletAttestationJwtHeaderV1_3 = z
  .object({
    ...zJwtHeader.shape,
    trust_chain: z.array(z.string()).nonempty().optional(), // OPTIONAL in v1.3
    typ: z.literal("oauth-client-attestation+jwt"),
    x5c: z.array(z.string()).nonempty(), // REQUIRED in v1.3
  })
  .passthrough();

/**
 * JWT Payload schema for IT-Wallet v1.3 Wallet Attestation
 *
 * Version 1.3 specifics:
 * - Supports nbf (not before) claim
 * - Supports status claim for revocation mechanisms
 */
export const zWalletAttestationJwtPayloadV1_3 = z
  .object({
    ...zJwtPayload.shape,
    cnf: z.object({
      jwk: zJwk,
    }),
    exp: z.number(),
    iat: z.number(),
    iss: z.string(),
    nbf: z.number().optional(), // NEW in v1.3
    status: z
      .object({
        status_list: z.object({
          idx: z.number().int(),
          uri: z.string(),
        }),
      })
      .optional(), // NEW in v1.3 - status object for revocation
    sub: z.string(),
    wallet_link: z.string().url().optional(),
    wallet_name: z.string().optional(),
  })
  .passthrough();

/**
 * Wallet Attestation JWT type for v1.3
 * The JWT is returned as a compact string
 */
export type WalletAttestationJwtV1_3 = string;

/**
 * Zod schema for wallet attestation JWT validation (v1.3)
 * Validates that the result is a non-empty string
 */
export const zWalletAttestationJwtV1_3 = z.string().min(1);
