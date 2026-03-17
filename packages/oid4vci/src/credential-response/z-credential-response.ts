import { zAlgValueNotNone, zJwk } from "@pagopa/io-wallet-oauth2";
import { z } from "zod";

import type { CredentialResponseV1_0 } from "./v1.0/z-credential-response";
import type { CredentialResponseV1_3 } from "./v1.3/z-credential-response";

export {
  zCredentialResponseV1_0,
  zDeferredCredentialResponseV1_0,
} from "./v1.0/z-credential-response";

export type {
  CredentialResponseV1_0,
  DeferredCredentialResponseV1_0,
} from "./v1.0/z-credential-response";

export {
  zCredentialResponseV1_3,
  zDeferredCredentialResponseV1_3,
} from "./v1.3/z-credential-response";

export type {
  CredentialResponseV1_3,
  DeferredCredentialResponseV1_3,
} from "./v1.3/z-credential-response";

export {
  zCredentialObject,
  zImmediateCredentialResponse,
} from "./z-immediate-credential-response";

export type {
  CredentialObject,
  ImmediateCredentialResponse,
} from "./z-immediate-credential-response";

export type CredentialResponse =
  | CredentialResponseV1_0
  | CredentialResponseV1_3;

export const zCredentialResponseEncryption = z.looseObject({
  alg: zAlgValueNotNone,
  enc: z.string(),
  jwk: zJwk,
});

export type CredentialResponseEncryption = z.infer<
  typeof zCredentialResponseEncryption
>;
