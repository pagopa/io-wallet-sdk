import {
  CallbackContext,
  HashAlgorithm,
  HashCallback,
} from "@openid4vc/oauth2";
import { decodeUtf8String, encodeToBase64Url } from "@openid4vc/utils";

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

export async function verifyPkce(options: VerifyPkceOptions) {
  const calculatedCodeChallenge = await calculateCodeChallenge({
    codeChallengeMethod: options.codeChallengeMethod,
    codeVerifier: options.codeVerifier,
    hashCallback: options.callbacks.hash,
  });

  if (options.codeChallenge !== calculatedCodeChallenge) {
    throw new Oauth2Error(
      `Derived code challenge '${calculatedCodeChallenge}' from code_verifier '${options.codeVerifier}' using code challenge method '${options.codeChallengeMethod}' does not match the expected code challenge.`,
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
