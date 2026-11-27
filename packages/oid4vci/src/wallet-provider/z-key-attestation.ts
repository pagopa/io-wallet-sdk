import { zKeyStorageLevelV1_3 } from "@pagopa/io-wallet-oid-federation";
import {
  zCertificateChain,
  zItwSupportedSignatureAlg,
  zJwk,
  zTrustChain,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

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
 * For the moment, the specification doesn't restrict the key attestation signature algorithm
 * to a subset of those that must/should be allowed
 */
export const zKeyAttestationAlg = zItwSupportedSignatureAlg;

export const zKeyAttestationHeader = z.object({
  alg: zKeyAttestationAlg,
  kid: z.string(),
  trust_chain: zTrustChain.optional(),
  typ: z.literal("key-attestation+jwt"),
  x5c: zCertificateChain,
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

/**
 * Key Attestation payload for IT-Wallet v1.5: `iss` is removed and the
 * top-level `status` is replaced by `key_storage_status`.
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.5.0/en/wallet-provider-endpoint.html}
 */
export const zKeyAttestationPayloadV1_5 = zKeyAttestationPayload
  .omit({ iss: true, status: true })
  .extend({
    key_storage_status: z.object({
      exp: z.number(),
      status: zKeyAttestationStatus,
    }),
  });

export type KeyAttestationPayloadV1_5 = z.infer<
  typeof zKeyAttestationPayloadV1_5
>;

export const zKeyAttestationTypeHeader = z.literal("key-attestation+jwt");

export const keyAttestationTypeHeader = zKeyAttestationTypeHeader.value;
