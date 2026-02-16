import z from "zod";

/**
 * Zod schemas for MRTD (Machine Readable Travel Document) Proof of Possession flow.
 *
 * Implements IT-Wallet L2+ specification for eID Substantial Authentication with MRTD Verification.
 * Defines JWT structures and response formats for the multi-step document validation protocol.
 *
 * @see IT-Wallet L2+ specification Section 12.1.3 (eID Substantial Authentication with MRTD Verification)
 */

// --- MRTD Challenge JWT (received via redirect, typ: "mrtd-ias+jwt") ---

/** JWT header for MRTD challenge (Phase 3.1) */
export const zMrtdChallengeJwtHeader = z
  .object({
    alg: z.string(),
    kid: z.string(),
    typ: z.literal("mrtd-ias+jwt"),
  })
  .passthrough();
export type MrtdChallengeJwtHeader = z.infer<typeof zMrtdChallengeJwtHeader>;

/** JWT payload for MRTD challenge containing session correlation and endpoint parameters */
export const zMrtdChallengeJwtPayload = z
  .object({
    aud: z.string(),
    exp: z.number(),
    htm: z.literal("POST"),
    htu: z.string().url(),
    iat: z.number(),
    iss: z.string(),
    mrtd_auth_session: z.string(),
    mrtd_pop_jwt_nonce: z.string(),
    state: z.string(),
    status: z.literal("require_interaction"),
    type: z.literal("mrtd+ias"),
  })
  .passthrough();
export type MrtdChallengeJwtPayload = z.infer<typeof zMrtdChallengeJwtPayload>;

// --- MRTD PoP Init Response JWT (typ: "mrtd-ias-pop+jwt") ---

/** JWT header for MRTD PoP initialization response (Phase 3.3) */
export const zMrtdPopInitResponseJwtHeader = z
  .object({
    alg: z.string(),
    kid: z.string(),
    typ: z.literal("mrtd-ias-pop+jwt"),
  })
  .passthrough();
export type MrtdPopInitResponseJwtHeader = z.infer<
  typeof zMrtdPopInitResponseJwtHeader
>;

/** JWT payload for MRTD PoP initialization response containing challenge and nonce */
export const zMrtdPopInitResponseJwtPayload = z
  .object({
    aud: z.string(),
    challenge: z.string(),
    exp: z.number(),
    htm: z.literal("POST"),
    htu: z.string().url(),
    iat: z.number(),
    iss: z.string(),
    mrtd_pop_nonce: z.string(),
    mrz: z.string().optional(),
  })
  .passthrough();
export type MrtdPopInitResponseJwtPayload = z.infer<
  typeof zMrtdPopInitResponseJwtPayload
>;

// --- MRTD Validation JWT (created by Wallet, typ: "mrtd-ias+jwt") ---

/** MRTD application data from NFC reading (DG1, DG11, SOD) */
const zMrtdData = z
  .object({
    dg1: z.string(),
    dg11: z.string(),
    sod_mrtd: z.string(),
  })
  .passthrough();

/** IAS (Anti-Cloning) application data from NFC reading (public key, signed challenge, SOD) */
const zIasData = z
  .object({
    challenge_signed: z.string(),
    ias_pk: z.string(),
    sod_ias: z.string(),
  })
  .passthrough();

/** JWT header for MRTD validation (signed by Wallet Instance) */
export const zMrtdValidationJwtHeader = z
  .object({
    alg: z.string(),
    kid: z.string(),
    typ: z.literal("mrtd-ias+jwt"),
  })
  .passthrough();
export type MrtdValidationJwtHeader = z.infer<typeof zMrtdValidationJwtHeader>;

/** JWT payload for MRTD validation containing NFC-read document evidence */
export const zMrtdValidationJwtPayload = z
  .object({
    aud: z.string(),
    document_type: z.literal("cie"),
    exp: z.number(),
    ias: zIasData,
    iat: z.number(),
    iss: z.string(),
    mrtd: zMrtdData,
  })
  .passthrough();
export type MrtdValidationJwtPayload = z.infer<
  typeof zMrtdValidationJwtPayload
>;

// --- MRTD PoP Verify Response (JSON, not JWT) ---

/** Response from MRTD PoP verification endpoint (Phase 3.8) */
export const zMrtdPopVerifyResponse = z
  .object({
    mrtd_val_pop_nonce: z.string(),
    redirect_uri: z.string().url(),
    status: z.literal("require_interaction"),
    type: z.literal("redirect_to_web"),
  })
  .passthrough();
export type MrtdPopVerifyResponse = z.infer<typeof zMrtdPopVerifyResponse>;
