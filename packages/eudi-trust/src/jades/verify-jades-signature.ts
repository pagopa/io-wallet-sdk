import {
  CallbackContext,
  JwtPayload,
  decodeBase64,
  encodeToBase64Url,
  formatError,
  verifyJwt,
} from "@pagopa/io-wallet-utils";

import { JAdESError } from "../errors";
import { JAdESHeader } from "./z-jades";

export interface VerifyJAdESSignatureOptions {
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">;
  /** The compact JWS. */
  compact: string;
  /** The decoded header, validated with `zJAdESHeader`. */
  header: JAdESHeader;
  /** Validation time of `nbf` and `exp`. Defaults to the current time. */
  now?: Date;
  /** The decoded payload. */
  payload: JwtPayload;
  /** Do not check `nbf` and `exp`. */
  skipTimeBasedValidation?: boolean;
  /** An optional prefix to include in the error messages thrown by this function. */
  errorMessagePrefix?: string;
}

/**
 * Verifies a compact JAdES Baseline B signature (ETSI TS 119 182-1) made with
 * the first certificate of the `x5c` header.
 *
 * The signing certificate is not validated: use `validateCertificateChain` for
 * that. The header is expected to be already validated with `zJAdESHeader`.
 *
 * @throws {JAdESError} when the signature is invalid.
 */
export async function verifyJAdESSignature(
  options: VerifyJAdESSignatureOptions,
): Promise<void> {
  const { header, errorMessagePrefix } = options;
  const [signerCertificate] = header.x5c;

  const x5tO = header["x5t#o"];
  if (x5tO) {
    const digest = await options.callbacks.hash(
      decodeBase64(signerCertificate),
      x5tO.digAlg,
    );
    if (encodeToBase64Url(digest) !== x5tO.digVal) {
      throw new JAdESError(
        formatError(
          "x5t#o does not match the signer certificate",
          errorMessagePrefix,
        ),
        { code: "JADES_X5T_O_MISMATCH" },
      );
    }
  }

  try {
    await verifyJwt({
      compact: options.compact,
      header,
      now: options.now,
      payload: options.payload,
      signer: {
        alg: header.alg,
        method: "x5c",
        x5c: [signerCertificate],
      },
      skipTimeBasedValidation: options.skipTimeBasedValidation,
      verifyJwtCallback: options.callbacks.verifyJwt,
    });
  } catch (error) {
    const errorMessage =
      error instanceof Error
        ? error.message
        : "Failed to verify the JWT signature";

    throw new JAdESError(formatError(errorMessage, errorMessagePrefix), {
      code: "JADES_SIGNATURE_VERIFICATION_FAILED",
    });
  }
}
