import {
  CallbackContext,
  HashAlgorithm,
  HttpMethod,
  JwtSignerJwk,
} from "@openid4vc/oauth2";
import {
  dateToSeconds,
  decodeUtf8String,
  encodeToBase64Url,
  parseWithErrorHandling,
} from "@openid4vc/utils";
import { Base64 } from "js-base64";

import { CreateTokenDPoPError } from "../errors";
import {
  DpopJwtHeader,
  DpopJwtPayload,
  zDpopJwtHeader,
  zDpopJwtPayload,
} from "./z-dpop";

/**
 * Options for Token Request DPoP generation
 */
export interface CreateTokenDPoPOptions {
  /**
   * The access token to which the dpop jwt should be bound. Required
   * when the dpop will be sent along with an access token.
   *
   * If provided, the `hashCallback` parameter also needs to be provided
   */
  accessToken?: string;

  /**
   * Object containing callbacks for DPoP generation and signature
   */
  callbacks: Partial<Pick<CallbackContext, "generateRandom">> &
    Pick<CallbackContext, "hash" | "signJwt">;

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date;

  /**
   * jti claim for the DPoP JWT. If not provided, a random one will be generated
   * if a generateRandom callback is provided
   */
  jti?: string;

  /**
   * The signer of the dpop jwt. Only jwk signer allowed.
   */
  signer: JwtSignerJwk;

  /**
   * The request for which to create the dpop jwt
   */
  tokenRequest: {
    method: HttpMethod;
    url: string;
  };
}

/**
 * Creates a signed Token DPoP with the given cryptographic material and data.
 * It is used to create DPoP proofs for token requests and credential requests.
 * @param options {@link CreateTokenDPoPOptions}
 * @returns A Promise that resolves with an object containing the signed DPoP JWT and
 *          its corresponding public JWK
 * @throws {@link CreateTokenDPoPError} in case neither a default jti nor a generateRandom
 *         callback have been provided or the signJwt callback throws
 */
export async function createTokenDPoP(options: CreateTokenDPoPOptions) {
  // Calculate access token hash
  const ath = options.accessToken
    ? encodeToBase64Url(
        await options.callbacks.hash(
          decodeUtf8String(options.accessToken),
          HashAlgorithm.Sha256,
        ),
      )
    : undefined;

  const jti =
    options.jti ??
    (options.callbacks.generateRandom
      ? Base64.fromUint8Array(await options.callbacks.generateRandom(32), true)
      : undefined);

  if (!jti) {
    throw new CreateTokenDPoPError(
      "Error: neither a default jti nor a generateRandom callback have been provided",
    );
  }

  const header = parseWithErrorHandling(zDpopJwtHeader, {
    alg: options.signer.alg,
    jwk: options.signer.publicJwk,
    typ: "dpop+jwt",
  } satisfies DpopJwtHeader);
  try {
    const payload = parseWithErrorHandling(zDpopJwtPayload, {
      ath,
      htm: options.tokenRequest.method,
      htu: htuFromRequestUrl(options.tokenRequest.url),
      iat: dateToSeconds(options.issuedAt),
      jti,
    } satisfies DpopJwtPayload);

    return options.callbacks.signJwt(options.signer, {
      header,
      payload,
    });
  } catch (error) {
    throw new CreateTokenDPoPError(
      `Error during jwt signature, details: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

const htuFromRequestUrl = (requestUrl: string) => {
  const htu = new URL(requestUrl);
  htu.search = "";
  htu.hash = "";

  return htu.toString();
};
