import {
  type CallbackContext,
  jwtHeaderFromJwtSigner,
} from "@openid4vc/oauth2";
import { addSecondsToDate, dateToSeconds } from "@pagopa/io-wallet-utils";

import type { Jwk } from "../common/jwk/z-jwk";
import type { JweEncryptor, JwtSigner } from "../common/jwt/z-jwt";

import { Oauth2Error } from "../errors";
import {
  type JarAuthorizationRequest,
  type JarRequestObjectPayload,
  signedAuthorizationRequestJwtHeaderTyp,
} from "./z-jar";

export interface CreateJarRequestOptions {
  /**
   * Additional claims merged into the request object payload before
   * `authorizationRequestPayload`.
   */
  additionalJwtPayload?: Record<string, unknown>;

  /**
   * Authorization request claims used as JWT payload.
   */
  authorizationRequestPayload: JarRequestObjectPayload;

  /**
   * Cryptographic callbacks used to sign and optionally encrypt the JAR.
   */
  callbacks: Partial<Pick<CallbackContext, "encryptJwe">> &
    Pick<CallbackContext, "signJwt">;

  /**
   * Request object lifetime in seconds from `now`.
   */
  expiresInSeconds: number;

  /**
   * Encryptor configuration. When provided, the signed request object is wrapped
   * as JWE and returned as encrypted `request` value.
   */
  jweEncryptor?: JweEncryptor;

  /**
   * Signer configuration used to produce the request object JWT.
   */
  jwtSigner: JwtSigner;

  /**
   * Date that should be used as now. If not provided current date will be used.
   */
  now?: Date;

  /**
   * Optional request URI for by-reference JAR transmission.
   * When provided, `jarAuthorizationRequest` will include `request_uri` instead of `request`.
   */
  requestUri?: string;
}

export interface CreateJarRequestResult {
  /**
   * The signed (and optionally encrypted) JWT string representing the authorization request.
   * This value is included in `jarAuthorizationRequest` when `requestUri` is not provided.
   */
  authorizationRequestJwt: string;

  /**
   * The JWK used for encryption when `jweEncryptor` is provided, otherwise undefined.
   */
  encryptionJwk?: Jwk;

  /**
   * The JAR authorization request parameters to be sent to the authorization endpoint.
   * Contains either `request` or `request_uri` depending on the presence of `requestUri` in options.
   */
  jarAuthorizationRequest: JarAuthorizationRequest;

  /**
   * The JWK used for signing the request object JWT.
   */
  signerJwk: Jwk;
}

/**
 * Creates a JWT Secured Authorization Request (JAR) request payload.
 *
 * The request object is always signed, and optionally encrypted when `jweEncryptor`
 * is provided. The returned `jarAuthorizationRequest` is created in one of two forms:
 * - by-value, with `request`
 * - by-reference, with `request_uri`
 *
 * @param options - Parameters used to create the JAR request
 * @param options.additionalJwtPayload - Additional JWT claims merged before authorization claims
 * @param options.authorizationRequestPayload - Base authorization request JWT payload
 * @param options.callbacks - Callback context with required `signJwt` and optional `encryptJwe`
 * @param options.expiresInSeconds - JWT expiration offset in seconds
 * @param options.jweEncryptor - Optional JWE encryptor to wrap the signed JWT
 * @param options.jwtSigner - JWT signer used for request object signing
 * @param options.now - Optional reference time used for `iat` and `exp`
 * @param options.requestUri - Optional request URI for by-reference transmission
 *
 * @returns Signed (and optionally encrypted) authorization request data, signer key material,
 * and JAR request parameters for transmission.
 */
export async function createJarRequest(
  options: CreateJarRequestOptions,
): Promise<CreateJarRequestResult> {
  const {
    authorizationRequestPayload,
    callbacks,
    jweEncryptor,
    jwtSigner,
    requestUri,
  } = options;

  let authorizationRequestJwt: string | undefined;
  let encryptionJwk: Jwk | undefined;

  const now = options.now ?? new Date();

  const { jwt, signerJwk } = await callbacks.signJwt(jwtSigner, {
    header: {
      ...jwtHeaderFromJwtSigner(jwtSigner),
      typ: signedAuthorizationRequestJwtHeaderTyp,
    },
    payload: {
      ...options.additionalJwtPayload,
      ...authorizationRequestPayload,
      exp: dateToSeconds(addSecondsToDate(now, options.expiresInSeconds)),
      iat: dateToSeconds(now),
    },
  });

  authorizationRequestJwt = jwt;

  if (jweEncryptor) {
    if (!callbacks.encryptJwe) {
      throw new Oauth2Error(
        "callbacks.encryptJwe is required when jweEncryptor is provided",
      );
    }
    const encryptionResult = await callbacks.encryptJwe(
      jweEncryptor,
      authorizationRequestJwt,
    );
    authorizationRequestJwt = encryptionResult.jwe;
    encryptionJwk = encryptionResult.encryptionJwk;
  }

  const client_id = authorizationRequestPayload.client_id;
  const jarAuthorizationRequest: JarAuthorizationRequest = requestUri
    ? { client_id, request_uri: requestUri }
    : { client_id, request: authorizationRequestJwt };

  return {
    authorizationRequestJwt,
    encryptionJwk,
    jarAuthorizationRequest,
    signerJwk,
  };
}
