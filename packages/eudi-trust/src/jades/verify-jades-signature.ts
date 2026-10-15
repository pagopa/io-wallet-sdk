import {
  CallbackContext,
  JwtPayload,
  decodeBase64,
  encodeToBase64Url,
  verifyJwt,
} from "@pagopa/io-wallet-utils";

import { JAdESError } from "../errors";
import { JAdESHeader } from "./z-jades";

export interface VerifyJAdESSignatureOptions {
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">;
  compact: string;
  header: JAdESHeader;
  now?: Date;
  payload: JwtPayload;
  skipTimeBasedValidation?: boolean;
}

/**
 * Verify a compact JAdES B-B signature (ETSI TS 119 182-1): `x5t#o`, when
 * present, must be the digest of the first `x5c` certificate, and the signature
 * must be valid for that certificate. The header shape (see `zJAdESHeader`) is
 * expected to be already validated.
 *
 * @throws {JAdESError} when the signature is invalid.
 */
export async function verifyJAdESSignature(
  options: VerifyJAdESSignatureOptions,
): Promise<void> {
  const { header } = options;
  const [signerCertificate] = header.x5c;

  const x5tO = header["x5t#o"];
  if (x5tO) {
    const digest = await options.callbacks.hash(
      decodeBase64(signerCertificate),
      x5tO.digAlg,
    );
    if (encodeToBase64Url(digest) !== x5tO.digVal) {
      throw new JAdESError("x5t#o does not match the signer certificate", {
        code: "JADES_X5T_O_MISMATCH",
      });
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
    throw new JAdESError(
      error instanceof Error
        ? error.message
        : "Failed to verify the JWT signature",
      {
        code: "JADES_SIGNATURE_VERIFICATION_FAILED",
      },
    );
  }
}
