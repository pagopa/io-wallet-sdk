import { zJwk, zJwtHeader, zJwtPayload } from "@openid4vc/oauth2";
import { z } from "zod";

/**
 * JWT Header schema for IT-Wallet v1.0 Wallet Attestation
 *
 * Version 1.0 specifics:
 * - trust_chain is REQUIRED
 * - x5c is NOT supported
 */
export const zWalletAttestationJwtHeaderV1_0 = z
  .object({
    ...zJwtHeader.shape,
    trust_chain: z.array(z.string()).nonempty(), // REQUIRED in v1.0
    typ: z.literal("oauth-client-attestation+jwt"),
  })
  .passthrough();

/**
 * JWT Payload schema for IT-Wallet v1.0 Wallet Attestation
 *
 * Version 1.0 specifics:
 * - Standard claims only
 * - No nbf or status support
 */
export const zWalletAttestationJwtPayloadV1_0 = z
  .object({
    ...zJwtPayload.shape,
    aal: z.string(),
    cnf: z.object({
      jwk: zJwk,
    }),
    exp: z.number(),
    iat: z.number(),
    iss: z.string(),
    sub: z.string(),
    wallet_link: z.string().url().optional(),
    wallet_name: z.string().optional(),
  })
  .passthrough();

/**
 * Wallet Attestation JWT type for v1.0
 * The JWT is returned as a compact string
 */
export type WalletAttestationJwtV1_0 = string;

/**
 * Zod schema for wallet attestation JWT validation (v1.0)
 * Validates that the result is a non-empty string
 */
export const zWalletAttestationJwtV1_0 = z.string().min(1);
