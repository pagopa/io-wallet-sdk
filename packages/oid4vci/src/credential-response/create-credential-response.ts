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

/**
 * Creates a credential response according to the configured Italian Wallet specification version.
 *
 * Supports both immediate and deferred issuance flows, with optional JWE encryption of the
 * generated response payload.
 *
 * Version Differences:
 * - v1.0 deferred flow uses `lead_time`
 * - v1.3 deferred flow uses `interval`
 * - immediate flow has the same shape in both versions (`credentials`, optional `notification_id`)
 *
 * @param options - Credential response creation options, including version config, flow data,
 * and optional encryption settings.
 * @returns An object containing:
 * - `credentialResponse`: plain version-specific credential response JSON
 * - `credentialResponseJwt`: encrypted JWE string when encryption is requested
 * @throws {ItWalletSpecsVersionError} When the configured specification version is not supported.
 * @throws {ValidationError} When the generated response does not satisfy the version schema.
 * @throws {Oid4vciError} When encryption is requested but `callbacks.encryptJwe` is not provided.
 * @throws {CreateCredentialResponseError} For unexpected errors during response creation.
 *
 * @example v1.0 - Immediate flow without encryption
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 });
 * const result = await createCredentialResponse({
 *   config,
 *   flow: {
 *     credentials: [{ credential: "eyJ..." }],
 *     notificationId: "notif-123",
 *   },
 * });
 * // result.credentialResponse = { credentials: [{ credential: "eyJ..." }], notification_id: "notif-123" }
 * // result.credentialResponseJwt = undefined
 *
 * @example v1.3 - Immediate flow with encryption
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
 * const result = await createCredentialResponse({
 *   callbacks: { encryptJwe: myEncryptJweCallback },
 *   config,
 *   credentialResponseEncryption: {
 *     alg: "ECDH-ES",
 *     enc: "A256GCM",
 *     jwk: issuerEncryptionPublicJwk,
 *   },
 *   flow: {
 *     credentials: [{ credential: "eyJ..." }],
 *   },
 * });
 * // result.credentialResponse contains plain JSON
 * // result.credentialResponseJwt contains encrypted JWE
 *
 * @example v1.0 - Deferred flow without encryption
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 });
 * const result = await createCredentialResponse({
 *   config,
 *   flow: {
 *     leadTime: 300,
 *     transactionId: "tx-v1-0",
 *   },
 * });
 * // result.credentialResponse = { lead_time: 300, transaction_id: "tx-v1-0" }
 *
 * @example v1.3 - Deferred flow with encryption
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
 * const result = await createCredentialResponse({
 *   callbacks: { encryptJwe: myEncryptJweCallback },
 *   config,
 *   credentialResponseEncryption: {
 *     alg: "ECDH-ES",
 *     enc: "A256GCM",
 *     jwk: issuerEncryptionPublicJwk,
 *   },
 *   flow: {
 *     interval: 60,
 *     transactionId: "tx-v1-3",
 *   },
 * });
 * // result.credentialResponse = { interval: 60, transaction_id: "tx-v1-3" }
 * // result.credentialResponseJwt contains encrypted JWE
 */

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
