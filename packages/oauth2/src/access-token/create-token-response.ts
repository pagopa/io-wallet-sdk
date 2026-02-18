import {
  CallbackContext,
  HashAlgorithm,
  Jwk,
  JwtSigner,
  calculateJwkThumbprint,
  jwtHeaderFromJwtSigner,
} from "@openid4vc/oauth2";
import {
  addSecondsToDate,
  dateToSeconds,
  encodeToBase64Url,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { CreateTokenResponseError } from "../errors";
import {
  AccessTokenProfileJwtHeader,
  AccessTokenProfileJwtPayload,
  AccessTokenResponse,
  zAccessTokenProfileJwtHeader,
  zAccessTokenProfileJwtPayload,
  zAccessTokenResponse,
} from "./z-token";

export interface CreateAccessTokenResponseOptions {
  /**
   * Additional claims copied into both the access token JWT payload and token
   * response envelope.
   */
  additionalPayload?: Record<string, unknown>;

  /**
   * Intended recipient of the access token (`aud` claim).
   */
  audience: string;

  /**
   * Authorization server identifier (`iss` claim).
   */
  authorizationServer: string;

  /**
   * Runtime callbacks used to generate random values, compute JWK thumbprints,
   * and sign the access token JWT.
   */
  callbacks: Pick<CallbackContext, "generateRandom" | "hash" | "signJwt">;

  /**
   * OAuth client identifier (`client_id` claim).
   */
  clientId: string;

  /**
   * DPoP public key used to bind the access token (`cnf.jkt` claim).
   */
  dpop?: {
    jwk: Jwk;
  };

  /**
   * Access token lifetime in seconds, used for both `exp` and `expires_in`.
   */
  expiresInSeconds: number;

  /**
   * Optional "not before" timestamp in epoch seconds (`nbf` claim).
   */
  nbf?: number;

  /**
   * Reference time used for `iat` and `exp`. Defaults to current time.
   */
  now?: Date;

  /**
   * Optional refresh token included in the OAuth token response.
   */
  refreshToken?: string;

  /**
   * Optional scope string included in both the access token JWT payload and token
   * response envelope.
   */
  scope?: string;

  /**
   * Signer used to produce the access token JWT.
   */
  signer: JwtSigner;

  /**
   * Subject identifier represented by the access token (`sub` claim).
   */
  subject: string;

  /**
   * Token type returned in the OAuth token response.
   * NOTE: When using `Bearer` it is supposed to be used only for PDND Interoperability API, not for credential issuance flows.
   */
  tokenType: "Bearer" | "DPoP";
}

/**
 * Creates an OAuth 2.0 access token response where `access_token` is a signed
 * JWT access token profile (`typ=at+jwt`) and `token_type` is `DPoP` or `Bearer`.
 *
 * The JWT payload always includes `aud`, `iss`, `sub`, `client_id`, `iat`,
 * `exp`, and a random `jti`. When `dpop` is provided, `cnf.jkt` is added using
 * the SHA-256 JWK thumbprint.
 */
export async function createAccessTokenResponse(
  options: CreateAccessTokenResponseOptions,
) {
  try {
    const header = parseWithErrorHandling(zAccessTokenProfileJwtHeader, {
      ...jwtHeaderFromJwtSigner(options.signer),
      typ: "at+jwt",
    } satisfies AccessTokenProfileJwtHeader);

    if (options.tokenType === "DPoP" && !options.dpop) {
      throw new CreateTokenResponseError(
        "token_type is DPoP but dpop option is not provided. Please provide a DPoP public key in the dpop option or set tokenType to 'Bearer'.",
      );
    }

    const now = options.now ?? new Date();

    const payload = parseWithErrorHandling(zAccessTokenProfileJwtPayload, {
      aud: options.audience,
      client_id: options.clientId,
      cnf: options.dpop
        ? {
            jkt: await calculateJwkThumbprint({
              hashAlgorithm: HashAlgorithm.Sha256,
              hashCallback: options.callbacks.hash,
              jwk: options.dpop.jwk,
            }),
          }
        : undefined,
      exp: dateToSeconds(addSecondsToDate(now, options.expiresInSeconds)),
      iat: dateToSeconds(now),
      iss: options.authorizationServer,
      jti: encodeToBase64Url(await options.callbacks.generateRandom(32)),
      nbf: options.nbf,
      scope: options.scope,
      sub: options.subject,
      ...options.additionalPayload,
    } satisfies AccessTokenProfileJwtPayload);

    const { jwt } = await options.callbacks.signJwt(options.signer, {
      header,
      payload,
    });

    const accessTokenResponse = parseWithErrorHandling(zAccessTokenResponse, {
      access_token: jwt,
      expires_in: options.expiresInSeconds,
      refresh_token: options.refreshToken,
      token_type: options.tokenType,
      ...options.additionalPayload,
    } satisfies AccessTokenResponse);

    return accessTokenResponse;
  } catch (error) {
    if (error instanceof CreateTokenResponseError) {
      throw error;
    }
    throw new CreateTokenResponseError(
      `Error creating access token JWT: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
