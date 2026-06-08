import type { VerifyJwtCallback } from "../callback-context";

import { dateToSeconds } from "../../date";
import { JwtVerificationError } from "../../errors/errors";
import { JwtHeader, JwtPayload, JwtSigner, JwtSignerWithJwk } from "./z-jwt";

export interface VerifyJwtOptions {
  allowedSkewInSeconds?: number;
  compact: string;
  errorMessage?: string;
  expectedAudience?: string;
  expectedIssuer?: string;
  expectedNonce?: string;
  expectedSubject?: string;
  header: JwtHeader;
  now?: Date;
  payload: JwtPayload;
  requiredClaims?: (keyof JwtPayload)[];
  signer: JwtSigner;
  skipTimeBasedValidation?: boolean;
  verifyJwtCallback: VerifyJwtCallback;
}

export interface VerifyJwtReturn {
  signer: JwtSignerWithJwk;
}

// eslint-disable-next-line complexity
export async function verifyJwt(
  options: VerifyJwtOptions,
): Promise<VerifyJwtReturn> {
  const errorMessage =
    options.errorMessage ?? "Error during verification of jwt.";

  let signerJwk;
  try {
    const result = await options.verifyJwtCallback(options.signer, {
      compact: options.compact,
      header: options.header,
      payload: options.payload,
    });

    if (!result.verified) {
      throw new JwtVerificationError(errorMessage);
    }

    signerJwk = result.signerJwk;
  } catch (error) {
    if (error instanceof JwtVerificationError) {
      throw error;
    }

    throw new JwtVerificationError(errorMessage, { cause: error });
  }

  const nowInSeconds = dateToSeconds(options.now ?? new Date());
  const skewInSeconds = options.allowedSkewInSeconds ?? 0;
  const timeBasedValidation =
    options.skipTimeBasedValidation !== undefined
      ? !options.skipTimeBasedValidation
      : true;

  if (
    timeBasedValidation &&
    options.payload.nbf &&
    nowInSeconds < options.payload.nbf - skewInSeconds
  ) {
    throw new JwtVerificationError(
      `${errorMessage} jwt 'nbf' is in the future`,
    );
  }

  if (
    timeBasedValidation &&
    options.payload.exp &&
    nowInSeconds > options.payload.exp + skewInSeconds
  ) {
    throw new JwtVerificationError(`${errorMessage} jwt 'exp' is in the past`);
  }

  if (options.expectedAudience) {
    const { aud } = options.payload;
    if (
      (Array.isArray(aud) && !aud.includes(options.expectedAudience)) ||
      (typeof aud === "string" && aud !== options.expectedAudience)
    ) {
      throw new JwtVerificationError(
        `${errorMessage} jwt 'aud' does not match expected value.`,
      );
    }
  }

  if (
    options.expectedIssuer &&
    options.expectedIssuer !== options.payload.iss
  ) {
    throw new JwtVerificationError(
      `${errorMessage} jwt 'iss' does not match expected value.`,
    );
  }

  if (
    options.expectedNonce &&
    options.expectedNonce !== options.payload.nonce
  ) {
    throw new JwtVerificationError(
      `${errorMessage} jwt 'nonce' does not match expected value.`,
    );
  }

  if (
    options.expectedSubject &&
    options.expectedSubject !== options.payload.sub
  ) {
    throw new JwtVerificationError(
      `${errorMessage} jwt 'sub' does not match expected value.`,
    );
  }

  if (options.requiredClaims) {
    for (const claim of options.requiredClaims) {
      if (!options.payload[claim]) {
        throw new JwtVerificationError(
          `${errorMessage} jwt '${claim}' is missing.`,
        );
      }
    }
  }

  return {
    signer: {
      ...options.signer,
      publicJwk: signerJwk,
    },
  };
}
