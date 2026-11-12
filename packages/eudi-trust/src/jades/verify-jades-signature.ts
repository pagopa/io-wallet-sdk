import {
  CallbackContext,
  HashAlgorithm,
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
  /** An optional prefix to include in the error messages thrown by this function. */
  errorMessagePrefix?: string;
  /** The decoded header, validated with `zJAdESHeader`. */
  header: JAdESHeader;
  /** Validation time of `nbf` and `exp`. Defaults to the current time. */
  now?: Date;
  /** The decoded payload. */
  payload: JwtPayload;
  /** Do not check `nbf` and `exp`. */
  skipTimeBasedValidation?: boolean;
}

/**
 * Verifies a compact JAdES Baseline B signature (ETSI TS 119 182-1) made with
 * the first certificate of the `x5c` header.
 *
 * The claimed signing time `iat` must not be later than `now`.
 *
 * The signing certificate references `x5t#o`, `x5t#S256` and the first entry
 * of `sigX5ts`, when present, must match it; the other `sigX5ts` entries are
 * not checked.
 *
 * The signing certificate is not validated: use `validateCertificateChain` for
 * that. The header is expected to be already validated with `zJAdESHeader`.
 *
 * @throws {JAdESError} when the signature is invalid.
 */
export async function verifyJAdESSignature(
  options: VerifyJAdESSignatureOptions,
): Promise<void> {
  const { errorMessagePrefix, header } = options;
  const [signerCertificate] = header.x5c;

  const digestMatches = async (digAlg: HashAlgorithm, digVal: string) =>
    encodeToBase64Url(
      await options.callbacks.hash(decodeBase64(signerCertificate), digAlg),
    ) === digVal;

  const now = options.now ?? new Date();
  if (header.iat * 1000 > now.getTime()) {
    throw new JAdESError(
      formatError("iat is later than the validation time", errorMessagePrefix),
      { code: "JADES_IAT_IN_FUTURE" },
    );
  }

  for (const name of header.crit ?? []) {
    if (!(name in header)) {
      throw new JAdESError(
        formatError(
          `Critical header parameter ${name} is not present`,
          errorMessagePrefix,
        ),
        { code: "JADES_CRIT_PARAMETER_MISSING" },
      );
    }
  }

  const x5tO = header["x5t#o"];
  if (x5tO && !(await digestMatches(x5tO.digAlg, x5tO.digVal))) {
    throw new JAdESError(
      formatError(
        "x5t#o does not match the signer certificate",
        errorMessagePrefix,
      ),
      { code: "JADES_X5T_O_MISMATCH" },
    );
  }

  const x5tS256 = header["x5t#S256"];
  if (x5tS256 && !(await digestMatches(HashAlgorithm.Sha256, x5tS256))) {
    throw new JAdESError(
      formatError(
        "x5t#S256 does not match the signer certificate",
        errorMessagePrefix,
      ),
      { code: "JADES_X5T_S256_MISMATCH" },
    );
  }

  const [signerReference] = header.sigX5ts ?? [];
  if (
    signerReference &&
    !(await digestMatches(signerReference.digAlg, signerReference.digVal))
  ) {
    throw new JAdESError(
      formatError(
        "The first sigX5ts entry does not match the signer certificate",
        errorMessagePrefix,
      ),
      { code: "JADES_SIG_X5TS_MISMATCH" },
    );
  }

  try {
    await verifyJwt({
      compact: options.compact,
      header,
      now,
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
