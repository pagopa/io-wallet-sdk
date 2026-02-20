import {
  CallbackContext,
  jwtSignerFromJwt,
  verifyJwt,
} from "@openid4vc/oauth2";
import { decodeJwt } from "@pagopa/io-wallet-oauth2";

import {
  KeyAttestationHeader,
  KeyAttestationPayload,
  zKeyAttestationHeader,
  zKeyAttestationPayload,
} from "../wallet-provider/z-key-attestation";

/**
 * Options for verifying a key attestation JWT.
 */
export interface VerifyKeyAttestationJwtOptions {
  /**
   * Callback required for JWT signature verification.
   */
  callbacks: Pick<CallbackContext, "verifyJwt">;
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
 * @param options - Verification options and callbacks.
 * @returns Decoded header, payload, and signer.
 * @throws {Oauth2JwtParseError} If JWT decoding fails.
 * @throws {ValidationError} If schema validation fails.
 */
export async function verifyKeyAttestationJwt(
  options: VerifyKeyAttestationJwtOptions,
): Promise<VerifyKeyAttestationJwtResult> {
  const { header, payload } = decodeJwt({
    headerSchema: zKeyAttestationHeader,
    jwt: options.keyAttestationJwt,
    payloadSchema: zKeyAttestationPayload,
  });

  const { signer } = await verifyJwt({
    compact: options.keyAttestationJwt,
    errorMessage: "Key attestation JWT verification failed.",
    header,
    now: options.now,
    payload,
    signer: jwtSignerFromJwt({ header, payload }),
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  return { header, payload, signer };
}
