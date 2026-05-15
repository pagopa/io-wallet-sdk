import {
  CallbackContext,
  HashAlgorithm,
  HashCallback,
} from "@openid4vc/oauth2";
import { decodeUtf8String, encodeToBase64Url } from "@pagopa/io-wallet-utils";

import { Oauth2Error } from "./errors";

export const PkceCodeChallengeMethod = {
  Plain: "plain",
  S256: "S256",
} as const;

export type PkceCodeChallengeMethod =
  (typeof PkceCodeChallengeMethod)[keyof typeof PkceCodeChallengeMethod];

export interface CreatePkceOptions {
  /**
   * Also allows string values so it can be directly passed from the
   * 'code_challenge_methods_supported' metadata parameter
   */
  allowedCodeChallengeMethods?: (PkceCodeChallengeMethod | string)[];

  callbacks: Pick<CallbackContext, "generateRandom" | "hash">;

  /**
   * Code verifier to use. If not provided a value will be generated.
   */
  codeVerifier?: string;
}

export interface CreatePkceReturn {
  codeChallenge: string;
  codeChallengeMethod: PkceCodeChallengeMethod;
  codeVerifier: string;
}

/**
 * Creates a PKCE code verifier and challenge pair.
 *
 * @param options - PKCE creation options.
 * @param options.allowedCodeChallengeMethods - Code challenge methods supported by the server.
 * @param options.callbacks - Random generation and hashing callbacks.
 * @param options.codeVerifier - Optional existing verifier; generated when omitted.
 * @returns Generated verifier, challenge, and selected challenge method.
 * @throws {Oauth2Error} If no challenge method is available or the selected method is unsupported.
 */
export async function createPkce(
  options: CreatePkceOptions,
): Promise<CreatePkceReturn> {
  const allowedCodeChallengeMethods = options.allowedCodeChallengeMethods ?? [
    PkceCodeChallengeMethod.S256,
    PkceCodeChallengeMethod.Plain,
  ];

  if (allowedCodeChallengeMethods.length === 0) {
    throw new Oauth2Error(
      `Unable to create PKCE code verifier. 'allowedCodeChallengeMethods' is an empty array.`,
    );
  }

  const codeChallengeMethod = allowedCodeChallengeMethods.includes(
    PkceCodeChallengeMethod.S256,
  )
    ? PkceCodeChallengeMethod.S256
    : PkceCodeChallengeMethod.Plain;

  const codeVerifier =
    options.codeVerifier ??
    encodeToBase64Url(await options.callbacks.generateRandom(64));
  return {
    codeChallenge: await calculateCodeChallenge({
      codeChallengeMethod,
      codeVerifier,
      hashCallback: options.callbacks.hash,
    }),
    codeChallengeMethod,
    codeVerifier,
  };
}

export interface VerifyPkceOptions {
  callbacks: Pick<CallbackContext, "hash">;

  codeChallenge: string;
  codeChallengeMethod: PkceCodeChallengeMethod;

  /**
   * secure random code verifier
   */
  codeVerifier: string;
}

/**
 * Verifies that a PKCE code verifier matches a stored code challenge.
 *
 * @param options - PKCE verification options.
 * @param options.callbacks - Hashing callback.
 * @param options.codeChallenge - Expected code challenge.
 * @param options.codeChallengeMethod - Method used to compute the challenge.
 * @param options.codeVerifier - Verifier supplied by the client.
 * @returns Resolves when the verifier matches the challenge.
 * @throws {Oauth2Error} If the verifier does not match or the challenge method is unsupported.
 */
export async function verifyPkce(options: VerifyPkceOptions) {
  const calculatedCodeChallenge = await calculateCodeChallenge({
    codeChallengeMethod: options.codeChallengeMethod,
    codeVerifier: options.codeVerifier,
    hashCallback: options.callbacks.hash,
  });

  if (options.codeChallenge !== calculatedCodeChallenge) {
    throw new Oauth2Error(
      `PKCE verification failed: code_verifier does not match the stored code_challenge`,
    );
  }
}

async function calculateCodeChallenge(options: {
  codeChallengeMethod: PkceCodeChallengeMethod;
  codeVerifier: string;
  hashCallback: HashCallback;
}) {
  if (options.codeChallengeMethod === PkceCodeChallengeMethod.Plain) {
    return options.codeVerifier;
  }

  if (options.codeChallengeMethod === PkceCodeChallengeMethod.S256) {
    return encodeToBase64Url(
      await options.hashCallback(
        decodeUtf8String(options.codeVerifier),
        HashAlgorithm.Sha256,
      ),
    );
  }

  throw new Oauth2Error(
    `Unsupported code challenge method ${options.codeChallengeMethod}`,
  );
}
