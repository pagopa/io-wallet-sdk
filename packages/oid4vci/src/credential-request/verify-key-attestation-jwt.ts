import {
  CallbackContext,
  Oauth2JwtParseError,
  jwtSignerFromJwt,
  verifyJwt,
} from "@openid4vc/oauth2";
import { decodeJwt } from "@pagopa/io-wallet-oauth2";
import { ValidationError } from "@pagopa/io-wallet-utils";

import { VerifyKeyAttestationJwtError } from "../errors";
import {
  KeyAttestationHeader,
  KeyAttestationPayload,
  zKeyAttestationHeader,
  zKeyAttestationPayload,
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
   * Optional callback used to fetch and evaluate revocation status from the
   * status list referenced in `payload.status.status_list`.
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

/**
 * Decodes, validates, and verifies the signature of a key attestation JWT.
 *
 * The header and payload are validated against the `zKeyAttestationHeader` and
 * `zKeyAttestationPayload` schemas. The JWT signature is verified via the
 * `verifyJwt` callback.
 *
 * Revocation handling:
 * - If `fetchStatusList` is provided, this function checks whether the key
 *   attestation is revoked using `payload.status.status_list`.
 * - If `fetchStatusList` is omitted, revocation checking is the caller's
 *   responsibility.
 *
 * @param options - Verification options and callbacks.
 * @returns Decoded header, payload, and signer.
 * @throws {Oauth2JwtParseError} If JWT decoding fails.
 * @throws {ValidationError} If schema validation fails.
 */
export async function verifyKeyAttestationJwt(
  options: VerifyKeyAttestationJwtOptions,
): Promise<VerifyKeyAttestationJwtResult> {
  try {
    const { header, payload } = decodeJwt({
      errorMessagePrefix: "Error decoding key attestation JWT:",
      headerSchema: zKeyAttestationHeader,
      jwt: options.keyAttestationJwt,
      payloadSchema: zKeyAttestationPayload,
    });

    // Upstream verifyJwt/jwtSignerFromJwt still match IT-Wallet signature checks.
    const { signer } = await verifyJwt({
      compact: options.keyAttestationJwt,
      errorMessage: "Key attestation JWT verification failed.",
      header,
      now: options.now,
      payload,
      signer: jwtSignerFromJwt({ header, payload }),
      verifyJwtCallback: options.callbacks.verifyJwt,
    });

    if (options.fetchStatusList) {
      const { idx, uri } = payload.status.status_list;
      const isRevoked = await options.fetchStatusList({
        index: idx,
        uri,
      });

      if (isRevoked) {
        throw new VerifyKeyAttestationJwtError(
          `Key attestation has been revoked (status list: ${uri}, index: ${idx})`,
        );
      }
    }

    return { header, payload, signer };
  } catch (error) {
    if (
      error instanceof VerifyKeyAttestationJwtError ||
      error instanceof ValidationError ||
      error instanceof Oauth2JwtParseError
    ) {
      throw error;
    }

    throw new VerifyKeyAttestationJwtError(
      `Unexpected error during key attestation jwt verification: ${
        error instanceof Error ? error.message : String(error)
      }`,
      error,
    );
  }
}
