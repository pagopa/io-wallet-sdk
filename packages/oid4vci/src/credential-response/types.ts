import type { CallbackContext } from "@pagopa/io-wallet-oauth2";

import {
  type IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import type {
  CredentialObject,
  CredentialResponse,
  CredentialResponseEncryption,
} from "./z-credential-response";

export interface ImmediateFlowOptions {
  credentials: [CredentialObject, ...CredentialObject[]];
  notificationId?: string;
}

interface DeferredFlowOptions {
  transactionId: string;
}

export interface DeferredFlowOptionsV1_0 extends DeferredFlowOptions {
  leadTime: number;
}

export interface DeferredFlowOptionsV1_3 extends DeferredFlowOptions {
  interval: number;
}

interface CreateCredentialResponseOptionsBase {
  callbacks?: Pick<CallbackContext, "encryptJwe">;
  credentialResponseEncryption?: CredentialResponseEncryption;
}

export interface CreateCredentialResponseOptionsV1_0
  extends CreateCredentialResponseOptionsBase {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_0>;
  flow: DeferredFlowOptionsV1_0 | ImmediateFlowOptions;
}

export interface CreateCredentialResponseOptionsV1_3
  extends CreateCredentialResponseOptionsBase {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>;
  flow: DeferredFlowOptionsV1_3 | ImmediateFlowOptions;
}

export type CreateCredentialResponseOptions =
  | CreateCredentialResponseOptionsV1_0
  | CreateCredentialResponseOptionsV1_3;

export interface CreateCredentialResponseResult {
  credentialResponse: CredentialResponse;
  credentialResponseJwt?: string;
}

export type CreateCredentialResponseResultWithFlow<
  TResponse extends CredentialResponse,
> = {
  credentialResponse: TResponse;
} & Omit<CreateCredentialResponseResult, "credentialResponse">;
