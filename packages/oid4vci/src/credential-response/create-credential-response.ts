import type { CallbackContext, JweEncryptor } from "@pagopa/io-wallet-oauth2";

import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  ValidationError,
} from "@pagopa/io-wallet-utils";

import type {
  CreateCredentialResponseOptions,
  CreateCredentialResponseOptionsV1_0,
  CreateCredentialResponseOptionsV1_3,
  CreateCredentialResponseResult,
  CreateCredentialResponseResultWithFlow,
  DeferredFlowOptionsV1_0,
  DeferredFlowOptionsV1_3,
  ImmediateFlowOptions,
} from "./types";
import type {
  CredentialResponse,
  CredentialResponseEncryption,
  DeferredCredentialResponseV1_0,
  DeferredCredentialResponseV1_3,
} from "./z-credential-response";

import { CreateCredentialResponseError, Oid4vciError } from "../errors";
import * as V1_0 from "./v1.0/create-credential-response";
import * as V1_3 from "./v1.3/create-credential-response";
import { ImmediateCredentialResponse } from "./z-immediate-credential-response";

export type {
  CreateCredentialResponseOptions,
  CreateCredentialResponseOptionsV1_0,
  CreateCredentialResponseOptionsV1_3,
  CreateCredentialResponseResult,
  CreateCredentialResponseResultWithFlow,
  DeferredFlowOptionsV1_0,
  DeferredFlowOptionsV1_3,
  ImmediateFlowOptions,
} from "./types";

export function createCredentialResponse(
  options:
    | ({
        flow: ImmediateFlowOptions;
      } & Omit<CreateCredentialResponseOptionsV1_0, "flow">)
    | ({
        flow: ImmediateFlowOptions;
      } & Omit<CreateCredentialResponseOptionsV1_3, "flow">),
): Promise<CreateCredentialResponseResultWithFlow<ImmediateCredentialResponse>>;

export function createCredentialResponse(
  options: {
    flow: DeferredFlowOptionsV1_0;
  } & Omit<CreateCredentialResponseOptionsV1_0, "flow">,
): Promise<
  CreateCredentialResponseResultWithFlow<DeferredCredentialResponseV1_0>
>;

export function createCredentialResponse(
  options: {
    flow: DeferredFlowOptionsV1_3;
  } & Omit<CreateCredentialResponseOptionsV1_3, "flow">,
): Promise<
  CreateCredentialResponseResultWithFlow<DeferredCredentialResponseV1_3>
>;

export function createCredentialResponse(
  options: CreateCredentialResponseOptions,
): Promise<CreateCredentialResponseResult>;

export async function createCredentialResponse(
  options: CreateCredentialResponseOptions,
): Promise<CreateCredentialResponseResult> {
  try {
    const credentialResponse = buildVersionedResponse(options);

    const credentialResponseJwt = options.credentialResponseEncryption
      ? await encryptResponse(
          credentialResponse,
          options.credentialResponseEncryption,
          options.callbacks,
        )
      : undefined;

    return { credentialResponse, credentialResponseJwt };
  } catch (error) {
    if (
      error instanceof ItWalletSpecsVersionError ||
      error instanceof ValidationError ||
      error instanceof Oid4vciError
    ) {
      throw error;
    }
    throw new CreateCredentialResponseError(
      `Unexpected error during create credential response: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function buildVersionedResponse(
  options: CreateCredentialResponseOptions,
): CredentialResponse {
  const version = options.config.itWalletSpecsVersion;

  if (isCreateCredentialResponseOptionsV1_0(options)) {
    return V1_0.createCredentialResponseV1_0(options.flow);
  }

  if (isCreateCredentialResponseOptionsV1_3(options)) {
    return V1_3.createCredentialResponseV1_3(options.flow);
  }

  throw new ItWalletSpecsVersionError("createCredentialResponse", version, [
    ItWalletSpecsVersion.V1_0,
    ItWalletSpecsVersion.V1_3,
  ]);
}

function isCreateCredentialResponseOptionsV1_0(
  options: CreateCredentialResponseOptions,
): options is CreateCredentialResponseOptionsV1_0 {
  return options.config.isVersion(ItWalletSpecsVersion.V1_0);
}

function isCreateCredentialResponseOptionsV1_3(
  options: CreateCredentialResponseOptions,
): options is CreateCredentialResponseOptionsV1_3 {
  return options.config.isVersion(ItWalletSpecsVersion.V1_3);
}

async function encryptResponse(
  credentialResponse: CredentialResponse,
  credentialResponseEncryption: CredentialResponseEncryption,
  callbacks?: Pick<CallbackContext, "encryptJwe">,
): Promise<string> {
  if (!callbacks?.encryptJwe) {
    throw new Oid4vciError(
      "'credentialResponseEncryption' was provided but 'callbacks.encryptJwe' is not defined. Provide the 'encryptJwe' callback to encrypt the credential response.",
    );
  }

  const jweEncryptor: JweEncryptor = {
    alg: credentialResponseEncryption.alg,
    enc: credentialResponseEncryption.enc,
    method: "jwk",
    publicJwk: credentialResponseEncryption.jwk,
  };

  const { jwe } = await callbacks.encryptJwe(
    jweEncryptor,
    JSON.stringify(credentialResponse),
  );

  return jwe;
}
