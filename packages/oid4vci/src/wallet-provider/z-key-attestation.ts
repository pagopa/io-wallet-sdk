import { zJwk } from "@pagopa/io-wallet-oauth2";
import { zKeyStorageLevelV1_3 } from "@pagopa/io-wallet-oid-federation";
import { z } from "zod";

export const zStatusList = z.object({
  idx: z.number(),
  uri: z.string().url(),
});

export type StatusList = z.infer<typeof zStatusList>;

export const zKeyAttestationStatus = z.object({
  status_list: zStatusList,
});

export type KeyAttestationStatus = z.infer<typeof zKeyAttestationStatus>;

export const zKeyAttestationHeader = z.object({
  alg: z.literal("ES256"),
  kid: z.string(),
  trust_chain: z.array(z.string()).nonempty().optional(),
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
  key_storage: z.array(zKeyStorageLevelV1_3).nonempty(),
  status: zKeyAttestationStatus,
  user_authentication: z.array(zKeyStorageLevelV1_3).nonempty(),
});

export type KeyAttestationPayload = z.infer<typeof zKeyAttestationPayload>;

export const zKeyAttestationTypeHeader = z.literal("key-attestation+jwt");

export const keyAttestationTypeHeader = zKeyAttestationTypeHeader.value;
