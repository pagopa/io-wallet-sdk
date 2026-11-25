import {
  type CallbackContext,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  JwtParseError,
  type JwtSigner,
  ValidationError,
  decodeJwt,
  jwtSignerFromJwt,
  verifyJwt,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

import { VerifyKeyAttestationJwtError } from "../errors";
import {
  KeyAttestationHeader,
  KeyAttestationPayload,
  KeyAttestationPayloadV1_5,
  StatusList,
  zKeyAttestationHeader,
  zKeyAttestationPayload,
  zKeyAttestationPayloadV1_5,
} from "../wallet-provider/z-key-attestation";

export type FetchStatusListCallback = (statusList: {
  index: number;
  uri: string;
}) => Promise<boolean>;

/**
 * Options for verifying a key attestation JWT.
 */
export interface VerifyKeyAttestationJwtOptions {
  /**
   * Callback required for JWT signature verification.
   */
  callbacks: Pick<CallbackContext, "verifyJwt">;
  /**
   * SDK configuration selecting the key attestation profile.
   * When omitted, the v1.3/v1.4 profile is used.
   */
  config?: IoWalletSdkConfig;
  /**
   * Optional callback used to fetch and evaluate revocation status from the
   * status list referenced in `payload.status.status_list`
   * (`payload.key_storage_status.status.status_list` for v1.5).
   *
   * If omitted, revocation is not checked by this function.
   */
  fetchStatusList?: FetchStatusListCallback;
  /**
   * The compact key attestation JWT (`key-attestation+jwt`) to verify.
   */
  keyAttestationJwt: string;
  /**
   * Current time override. If not provided, the current time is used.
   */
  now?: Date;
}

/**
 * Result of a successful key attestation JWT verification.
 */
export interface VerifyKeyAttestationJwtResult {
  /** Parsed and validated key attestation JWT header. */
  header: KeyAttestationHeader;
  /** Parsed and validated key attestation JWT payload, including `attested_keys`. */
  payload: KeyAttestationPayload;
  /** The resolved signer that was used to verify the JWT. */
  signer: Awaited<ReturnType<typeof verifyJwt>>["signer"];
}

export type VerifyKeyAttestationJwtOptionsV1_5 = {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_5>;
} & Omit<VerifyKeyAttestationJwtOptions, "config">;

/**
 * Result of a successful v1.5 key attestation JWT verification.
 */
export type VerifyKeyAttestationJwtResultV1_5 = {
  payload: KeyAttestationPayloadV1_5;
} & Omit<VerifyKeyAttestationJwtResult, "payload">;

/**
 * Decodes, validates, and verifies the signature of a key attestation JWT.
 *
 * The header and payload are validated against the `zKeyAttestationHeader` and
 * `zKeyAttestationPayload` schemas. The JWT signature is verified via the
 * `verifyJwt` callback.
 *
 * For v1.5 the payload has no `iss` and carries `key_storage_status`; the JWT
 * is verified only with the `x5c` signer, so the `verifyJwt` callback MUST
 * validate the certificate chain against the National Wallet Trust Anchor.
 *
 * Revocation handling:
 * - If `fetchStatusList` is provided, this function checks whether the key
 *   attestation is revoked using `payload.status.status_list`
 *   (`payload.key_storage_status.status.status_list` for v1.5).
 * - If `fetchStatusList` is omitted, revocation checking is the caller's
 *   responsibility.
 *
 * @param options - Verification options and callbacks.
 * @returns Decoded header, payload, and signer.
 * @throws {JwtParseError} If JWT decoding fails.
 * @throws {ValidationError} If schema validation fails.
 */
export async function verifyKeyAttestationJwt(
  options: VerifyKeyAttestationJwtOptionsV1_5,
): Promise<VerifyKeyAttestationJwtResultV1_5>;

export async function verifyKeyAttestationJwt(
  options: VerifyKeyAttestationJwtOptions,
): Promise<VerifyKeyAttestationJwtResult>;

export async function verifyKeyAttestationJwt(
  options: VerifyKeyAttestationJwtOptions,
): Promise<VerifyKeyAttestationJwtResult | VerifyKeyAttestationJwtResultV1_5> {
  try {
    if (options.config?.isVersion(ItWalletSpecsVersion.V1_5)) {
      return await verifyKeyAttestationWithProfile(options, {
        allowedSignerMethods: ["x5c"],
        getStatusList: (payload) =>
          payload.key_storage_status.status.status_list,
        payloadSchema: zKeyAttestationPayloadV1_5,
      });
    }

    return await verifyKeyAttestationWithProfile(options, {
      getStatusList: (payload) => payload.status.status_list,
      payloadSchema: zKeyAttestationPayload,
    });
  } catch (error) {
    if (
      error instanceof VerifyKeyAttestationJwtError ||
      error instanceof ValidationError ||
      error instanceof JwtParseError
    ) {
      throw error;
    }

    throw new VerifyKeyAttestationJwtError(
      `Unexpected error during key attestation jwt verification: ${
        error instanceof Error ? error.message : String(error)
      }`,
      { cause: error },
    );
  }
}

async function verifyKeyAttestationWithProfile<
  TPayload extends KeyAttestationPayload | KeyAttestationPayloadV1_5,
>(
  options: VerifyKeyAttestationJwtOptions,
  profile: {
    allowedSignerMethods?: JwtSigner["method"][];
    getStatusList: (payload: TPayload) => StatusList;
    payloadSchema: z.ZodType<TPayload>;
  },
) {
  const { header, payload } = decodeJwt({
    errorMessagePrefix: "Error decoding key attestation JWT:",
    headerSchema: zKeyAttestationHeader,
    jwt: options.keyAttestationJwt,
    payloadSchema: profile.payloadSchema,
  });

  const { signer } = await verifyJwt({
    compact: options.keyAttestationJwt,
    errorMessage: "Key attestation JWT verification failed.",
    header,
    now: options.now,
    payload,
    signer: jwtSignerFromJwt({
      allowedSignerMethods: profile.allowedSignerMethods,
      header,
      payload: { iss: "iss" in payload ? payload.iss : undefined },
    }),
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  if (options.fetchStatusList) {
    const { idx, uri } = profile.getStatusList(payload);
    const isRevoked = await options.fetchStatusList({ index: idx, uri });

    if (isRevoked) {
      throw new VerifyKeyAttestationJwtError(
        `Key attestation has been revoked (status list: ${uri}, index: ${idx})`,
      );
    }
  }

  return { header, payload, signer };
}
