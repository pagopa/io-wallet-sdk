import { zJwk, zTrustChain } from "@pagopa/io-wallet-oauth2";
import { z } from "zod";

export const zKeyStorageLevel = z.enum([
  "iso_18045_high",
  "iso_18045_moderate",
  "iso_18045_basic",
]);

export type KeyStorageLevel = z.infer<typeof zKeyStorageLevel>;

export const zStatusList = z.object({
  idx: z.number(),
  uri: z.url(),
});

export type StatusList = z.infer<typeof zStatusList>;

export const zKeyAttestationStatus = z.object({
  status_list: zStatusList,
});

export type KeyAttestationStatus = z.infer<typeof zKeyAttestationStatus>;

/**
 * For the moment, these are all the supported algorithms in both
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/algorithms.html#cryptographic-algorithms|v1.3.3} and
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.0.2/en/algorithms.html#cryptographic-algorithms|v1.0.2},
 * and in both specifications the `alg` field MUST be one of those values.
 */
export const zKeyAttestationAlg = z.enum([
  "ES256",
  "ES384",
  "ES512",
  "PS256",
  "PS384",
  "PS512",
]);

export const zKeyAttestationHeader = z.object({
  alg: zKeyAttestationAlg,
  kid: z.string(),
  trust_chain: zTrustChain.optional(),
  typ: z.literal("key-attestation+jwt"),
  x5c: z.array(z.string()).nonempty(),
});

export type KeyAttestationHeader = z.infer<typeof zKeyAttestationHeader>;

export const zKeyAttestationPayload = z.object({
  attested_keys: z.array(zJwk).nonempty(),
  certification: z.string().optional(),
  exp: z.number(),
  iat: z.number(),
  iss: z.string(),
  key_storage: z.array(zKeyStorageLevel).nonempty(),
  status: zKeyAttestationStatus,
  user_authentication: z.array(zKeyStorageLevel).nonempty(),
});

export type KeyAttestationPayload = z.infer<typeof zKeyAttestationPayload>;

export const zKeyAttestationTypeHeader = z.literal("key-attestation+jwt");

export const keyAttestationTypeHeader = zKeyAttestationTypeHeader.value;
