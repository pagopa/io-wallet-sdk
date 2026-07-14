import {
  CallbackContext,
  type GenerateRandomCallback,
  HashAlgorithm,
  JwtSigner,
  calculateJwkThumbprint,
} from "@openid4vc/oauth2";
import {
  addSecondsToDate,
  dateToSeconds,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { Jwk } from "../common/jwk/z-jwk";
import { jwtHeaderFromJwtSigner } from "../common/jwt/decode-jwt-header";
import { CreateTokenResponseError } from "../errors";
import {
  AccessTokenProfileJwtHeader,
  AccessTokenProfileJwtPayload,
  AccessTokenResponse,
  RefreshTokenProfileJwtHeader,
  RefreshTokenProfileJwtPayload,
  zAccessTokenProfileJwtHeader,
  zAccessTokenProfileJwtPayload,
  zAccessTokenResponse,
  zRefreshTokenProfileJwtHeader,
  zRefreshTokenProfileJwtPayload,
} from "./z-token";

const UUID_BYTE_LENGTH = 16;

/**
 * Generates an RFC 4122 version 4 UUID using 16 random bytes obtained through
 * the supplied `generateRandom` callback.
 *
 * @param generateRandom - Callback used to source cryptographically secure random bytes.
 * @returns Canonical lowercase UUID v4 string.
 */
async function generateUuidV4(
  generateRandom: GenerateRandomCallback,
): Promise<string> {
  const bytes = await generateRandom(UUID_BYTE_LENGTH);
  // RFC 4122 requires setting the version (0100) and variant (10) bits directly.
  // eslint-disable-next-line no-bitwise
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  // eslint-disable-next-line no-bitwise
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;

  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .match(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/);

  if (!hex) {
    throw new CreateTokenResponseError(
      "Unable to generate a valid UUID v4 from the provided random bytes.",
    );
  }

  return `${hex[1]}-${hex[2]}-${hex[3]}-${hex[4]}-${hex[5]}`;
}

/**
 * Resolves the `kid` to include in the Refresh Token JOSE header.
 *
 * @param signer - Signer descriptor used to sign the Refresh Token.
 * @returns The signer's key identifier, or `undefined` if none can be resolved.
 */
function resolveRefreshTokenKid(signer: JwtSigner): string | undefined {
  if (signer.kid) {
    return signer.kid;
  }
  if (signer.method === "did") {
    return signer.didUrl;
  }
  if (signer.method === "jwk") {
    return signer.publicJwk.kid;
  }
  return undefined;
}

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
   * Requests issuance of a DPoP-bound Refresh Token JWT by specifying its
   * lifetime in seconds. The Refresh Token `exp` is set to `now +
   * refreshTokenExpiresInSeconds` and must be later than the Access Token
   * `exp` (`nbf` of the Refresh Token).
   *
   * Requires `tokenType` to be `DPoP` and `dpop` to be provided. Omit this
   * option to keep the specification's optional Refresh Token behavior
   * (e.g. Bearer-only PDND responses).
   */
  refreshTokenExpiresInSeconds?: number;

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
 *
 * When `refreshTokenExpiresInSeconds` is provided, a DPoP-bound Refresh Token
 * JWT (`typ=rt+jwt`) is generated, signed, and returned as `refresh_token`.
 * Refresh Token issuance requires `tokenType` to be `DPoP` with a `dpop`
 * public key, and results in `nbf` equal to the Access Token `exp` and `exp`
 * later than that.
 *
 * @param options - Access token response creation options.
 * @returns OAuth token response with a signed access token JWT, and a signed Refresh Token JWT when requested.
 * @throws {CreateTokenResponseError} If DPoP binding is required but missing, if Refresh Token issuance is requested without a valid DPoP configuration or lifetime, if the signer has no resolvable `kid` for the Refresh Token, or if response creation otherwise fails, including validation failures from the generated JWT headers or payloads.
 * @throws {ValidationError} If the generated JWT header or payload fails validation.
 */
export async function createAccessTokenResponse(
  options: CreateAccessTokenResponseOptions,
) {
  try {
    const now = options.now ?? new Date();

    if (options.tokenType === "DPoP" && !options.dpop) {
      throw new CreateTokenResponseError(
        "token_type is DPoP but dpop option is not provided. Please provide a DPoP public key in the dpop option or set tokenType to 'Bearer'.",
      );
    }

    if (
      options.refreshTokenExpiresInSeconds !== undefined &&
      (options.tokenType !== "DPoP" || !options.dpop)
    ) {
      throw new CreateTokenResponseError(
        "refreshTokenExpiresInSeconds was provided but Refresh Token issuance requires tokenType to be 'DPoP' with a dpop public key.",
      );
    }

    if (
      options.refreshTokenExpiresInSeconds !== undefined &&
      options.refreshTokenExpiresInSeconds <= options.expiresInSeconds
    ) {
      throw new CreateTokenResponseError(
        `refreshTokenExpiresInSeconds (${options.refreshTokenExpiresInSeconds}) must be greater than expiresInSeconds (${options.expiresInSeconds}) so the Refresh Token remains usable after the Access Token expires.`,
      );
    }

    const dpopJkt = options.dpop
      ? await calculateJwkThumbprint({
          hashAlgorithm: HashAlgorithm.Sha256,
          hashCallback: options.callbacks.hash,
          jwk: options.dpop.jwk,
        })
      : undefined;

    const accessTokenExpiresAt = addSecondsToDate(
      now,
      options.expiresInSeconds,
    );

    const header = parseWithErrorHandling(zAccessTokenProfileJwtHeader, {
      ...jwtHeaderFromJwtSigner(options.signer),
      typ: "at+jwt",
    } satisfies AccessTokenProfileJwtHeader);

    const payload = parseWithErrorHandling(zAccessTokenProfileJwtPayload, {
      ...options.additionalPayload,
      aud: options.audience,
      client_id: options.clientId,
      cnf: dpopJkt ? { jkt: dpopJkt } : undefined,
      exp: dateToSeconds(accessTokenExpiresAt),
      iat: dateToSeconds(now),
      iss: options.authorizationServer,
      jti: await generateUuidV4(options.callbacks.generateRandom),
      nbf: options.nbf,
      scope: options.scope,
      sub: options.subject,
    } satisfies AccessTokenProfileJwtPayload);

    const { jwt } = await options.callbacks.signJwt(options.signer, {
      header,
      payload,
    });

    let refreshToken: string | undefined;

    if (options.refreshTokenExpiresInSeconds !== undefined && dpopJkt) {
      const kid = resolveRefreshTokenKid(options.signer);
      if (!kid) {
        throw new CreateTokenResponseError(
          "Unable to resolve a kid for the Refresh Token JOSE header. Provide signer.kid or a publicJwk.kid.",
        );
      }

      const refreshTokenHeader = parseWithErrorHandling(
        zRefreshTokenProfileJwtHeader,
        {
          alg: options.signer.alg,
          kid,
          typ: "rt+jwt",
        } satisfies RefreshTokenProfileJwtHeader,
      );

      const refreshTokenPayload = parseWithErrorHandling(
        zRefreshTokenProfileJwtPayload,
        {
          aud: options.authorizationServer,
          client_id: options.clientId,
          cnf: { jkt: dpopJkt },
          exp: dateToSeconds(
            addSecondsToDate(now, options.refreshTokenExpiresInSeconds),
          ),
          iat: dateToSeconds(now),
          iss: options.authorizationServer,
          jti: await generateUuidV4(options.callbacks.generateRandom),
          nbf: dateToSeconds(accessTokenExpiresAt),
          sub: options.subject,
        } satisfies RefreshTokenProfileJwtPayload,
      );

      const refreshTokenSignResult = await options.callbacks.signJwt(
        options.signer,
        {
          header: refreshTokenHeader,
          payload: refreshTokenPayload,
        },
      );

      refreshToken = refreshTokenSignResult.jwt;
    }

    const accessTokenResponse = parseWithErrorHandling(zAccessTokenResponse, {
      ...options.additionalPayload,
      access_token: jwt,
      expires_in: options.expiresInSeconds,
      refresh_token: refreshToken,
      token_type: options.tokenType,
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
