import { CallbackContext, HttpMethod, JwtSigner } from "@openid4vc/oauth2";
import { Base64 } from "js-base64";

import { CreateTokenDPoPError } from "../errors";

/**
 * Options for Token Request DPoP generation
 */
export interface CreateTokenDPoPOptions {
  /**
   * Object containing callbacks for DPoP generation and signature
   */
  callbacks: Partial<Pick<CallbackContext, "generateRandom">> &
    Pick<CallbackContext, "signJwt">;

  /**
   * Customizable headers for DPoP signing.
   * As per technical specifications, the key typ will be set to 'dpop+jwt',
   * overriding any custom value passed. In case the alg and jwk properties
   * will not be set, the responsibility of doing so is left to the signJwt
   * callback, which may as well override such keys if passed
   */
  header: { alg: string } & Record<string, unknown>;

  /**
   * Customizable payload for DPoP signing.
   * Any field might be overridden by the signJwt callback
   */
  payload: {
    htm: HttpMethod;
    htu: string;
    jti?: string;
  } & Record<string, unknown>;

  /**
   * Jwt Signer corresponding to the DPoP's Crypto Context
   */
  signer: JwtSigner;
}

/**
 * Creates a signed Token DPoP with the given cryptographic material and data.
 * @param options {@link CreateTokenDPoPOptions}
 * @returns A Promise that resolves with an object containing the signed DPoP JWT and
 *          its corresponding public JWK
 * @throws {@link CreateTokenDPoPError} in case neither a default jti nor a generateRandom
 *         callback have been provided or the signJwt callback throws
 */
export async function createTokenDPoP(options: CreateTokenDPoPOptions) {
  const jti =
    options.payload.jti ??
    (options.callbacks.generateRandom
      ? Base64.fromUint8Array(await options.callbacks.generateRandom(32), true)
      : undefined);

  if (!jti) {
    throw new CreateTokenDPoPError(
      "Error: neither a default jti nor a generateRandom callback have been provided",
    );
  }
  try {
    return options.callbacks.signJwt(options.signer, {
      header: {
        ...options.header,
        typ: "dpop+jwt",
      },
      payload: {
        ...options.payload,
        jti,
      },
    });
  } catch (error) {
    throw new CreateTokenDPoPError(
      `Error during jwt signature, details: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
