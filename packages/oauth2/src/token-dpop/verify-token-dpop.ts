import {
  CallbackContext,
  HashAlgorithm,
  calculateJwkThumbprint,
  verifyJwt,
} from "@openid4vc/oauth2";
import {
  RequestLike,
  decodeUtf8String,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";

import { decodeJwt } from "../common/jwt/decode-jwt";
import { Oauth2Error } from "../errors";
import { htuFromRequestUrl } from "./dpop-utils";
import { zDpopJwtHeader, zDpopJwtPayload } from "./z-dpop";

export interface VerifyTokenDPoPOptions {
  /**
   * Access token to which the dpop jwt is bound. If provided the sha-256 hash of the
   * access token needs to match the 'ath' claim.
   */
  accessToken?: string;

  /**
   * Allowed dpop signing alg values. If not provided
   * any alg values are allowed and it's up to the `verifyJwtCallback`
   * to handle the alg.
   */
  allowedSigningAlgs?: string[];

  /**
   * Callbacks used for verifying dpop jwt
   */
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">;

  /**
   * The compact dpop jwt.
   */
  dpopJwt: string;

  /**
   * The expected jwk thumprint 'jti' confirmation method. If provided the thumprint of the
   * jwk used to sign the dpop jwt must match this provided thumbprint value. The 'jti' value
   * can be extracted from the access token payload, or if opaque tokens are used can be retrieved
   * using token introspection.
   */
  expectedJwkThumbprint?: string;

  /**
   * Expected nonce in the payload. If not provided the nonce won't be validated.
   */
  expectedNonce?: string;

  /**
   * The current time to use when verifying the JWTs.
   * If not provided current time will be used.
   *
   * @default new Date()
   */
  now?: Date;

  /**
   * The request for which to verify the dpop jwt
   */
  request: RequestLike;
}

export async function verifyTokenDPoP(options: VerifyTokenDPoPOptions) {
  const { header, payload } = decodeJwt({
    headerSchema: zDpopJwtHeader,
    jwt: options.dpopJwt,
    payloadSchema: zDpopJwtPayload,
  });

  if (
    options.allowedSigningAlgs &&
    !options.allowedSigningAlgs.includes(header.alg)
  ) {
    throw new Oauth2Error(
      `dpop jwt uses alg value '${header.alg}' but allowed dpop signing alg values are ${options.allowedSigningAlgs.join(", ")}.`,
    );
  }

  if (options.expectedNonce) {
    if (!payload.nonce) {
      throw new Oauth2Error(
        `Dpop jwt does not have a nonce value, but expected nonce value '${options.expectedNonce}'`,
      );
    }

    if (payload.nonce !== options.expectedNonce) {
      throw new Oauth2Error(
        `Dpop jwt contains nonce value '${payload.nonce}', but expected nonce value '${options.expectedNonce}'`,
      );
    }
  }

  if (options.request.method !== payload.htm) {
    throw new Oauth2Error(
      `Dpop jwt contains htm value '${payload.htm}', but expected htm value '${options.request.method}'`,
    );
  }

  const expectedHtu = htuFromRequestUrl(options.request.url);
  if (expectedHtu !== payload.htu) {
    throw new Oauth2Error(
      `Dpop jwt contains htu value '${payload.htu}', but expected htu value '${expectedHtu}'.`,
    );
  }

  if (options.accessToken) {
    const expectedAth = encodeToBase64Url(
      await options.callbacks.hash(
        decodeUtf8String(options.accessToken),
        HashAlgorithm.Sha256,
      ),
    );

    if (!payload.ath) {
      throw new Oauth2Error(
        `Dpop jwt does not have a ath value, but expected ath value '${expectedAth}'.`,
      );
    }

    if (payload.ath !== expectedAth) {
      throw new Oauth2Error(
        `Dpop jwt contains ath value '${payload.ath}', but expected ath value '${expectedAth}'.`,
      );
    }
  }

  const jwkThumbprint = await calculateJwkThumbprint({
    hashAlgorithm: HashAlgorithm.Sha256,
    hashCallback: options.callbacks.hash,
    jwk: header.jwk,
  });

  if (
    options.expectedJwkThumbprint &&
    options.expectedJwkThumbprint !== jwkThumbprint
  ) {
    throw new Oauth2Error(
      `Dpop is signed with jwk with thumbprint value '${jwkThumbprint}', but expect jwk thumbprint value '${options.expectedJwkThumbprint}'`,
    );
  }

  await verifyJwt({
    compact: options.dpopJwt,
    errorMessage: "dpop jwt verification failed",
    header,
    now: options.now,
    payload,
    signer: {
      alg: header.alg,
      method: "jwk",
      publicJwk: header.jwk,
    },
    verifyJwtCallback: options.callbacks.verifyJwt,
  });

  return {
    header,
    jwkThumbprint,
    payload,
  };
}
