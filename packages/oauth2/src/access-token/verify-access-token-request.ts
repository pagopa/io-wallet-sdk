import {
  AuthorizationServerMetadata,
  CallbackContext,
  Jwk,
} from "@openid4vc/oauth2";
import { RequestLike } from "@pagopa/io-wallet-utils";

import {
  ClientAttestationOptions,
  VerifiedClientAttestationJwt,
  VerifiedClientAttestationPopJwt,
  verifyClientAttestation,
} from "../client-attestation";
import { Oauth2Error } from "../errors";
import { PkceCodeChallengeMethod, verifyPkce } from "../pkce";
import { verifyTokenDPoP } from "../token-dpop";
import { ParsedAccessTokenAuthorizationCodeRequestGrant } from "./parse-token-request";
import { AccessTokenRequest } from "./z-token";

export interface VerifyAccessTokenRequestPkce {
  codeChallenge: string;
  codeChallengeMethod: PkceCodeChallengeMethod;
  codeVerifier: string;
}

export interface VerifyAccessTokenRequestDpop {
  /**
   * Allowed dpop signing alg values. If not provided
   * any alg values are allowed and it's up to the `verifyJwtCallback`
   * to handle the alg.
   */
  allowedSigningAlgs?: string[];

  /**
   * The dpop jwt from the access token request
   */
  jwt: string;
}

export interface VerifyAccessTokenRequestOptions {
  /**
   * The access token request to verify
   */
  accessTokenRequest: AccessTokenRequest;

  /**
   * The authorization server metadata
   */
  authorizationServerMetadata: AuthorizationServerMetadata;

  /**
   * Callbacks used during verification
   */
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">;

  /**
   * Options for verifying the client attestation
   */
  clientAttestation: ClientAttestationOptions;

  /**
   * The expiration date of the authorization code
   */
  codeExpiresAt?: Date;

  /**
   * The dpop verification options
   */
  dpop: VerifyAccessTokenRequestDpop;

  /**
   * The expected authorization code
   */
  expectedCode: string;

  /**
   * The parsed authorization code grant
   */
  grant: ParsedAccessTokenAuthorizationCodeRequestGrant;

  /**
   * The current date/time. If not provided, the current system date/time will be used.
   */
  now?: Date;

  /**
   * The pkce options including code verifier, challenge and method
   */
  pkce: VerifyAccessTokenRequestPkce;

  /**
   * The HTTP request information
   */
  request: RequestLike;
}

export interface VerifyAccessTokenRequestResult {
  clientAttestation: {
    clientAttestation: VerifiedClientAttestationJwt;
    clientAttestationPop: VerifiedClientAttestationPopJwt;
  };

  dpop: {
    jwk: Jwk;

    /**
     * base64url encoding of the JWK SHA-256 Thumbprint (according to [RFC7638])
     * of the DPoP public key (in JWK format)
     */
    jwkThumbprint: string;
  };
}

/**
 * Verifies an authorization code token request by validating PKCE, DPoP, and client attestation.
 *
 * This function performs comprehensive validation of an OAuth 2.0 authorization code token request
 * according to Italian IT-Wallet specifications, including:
 * - PKCE code verifier validation against the stored code challenge
 * - DPoP proof JWT verification and JWK thumbprint extraction
 * - Client attestation JWT and attestation PoP JWT verification
 * - Authorization code validity and expiration checks
 *
 * @param options - Configuration options for token request verification
 * @returns A promise that resolves with verified client attestation and DPoP information
 * @throws {Oauth2Error} If the authorization code is invalid or expired
 * @throws {Oauth2Error} If PKCE verification fails
 * @throws {Oauth2Error} If DPoP verification fails
 * @throws {Oauth2Error} If client attestation verification fails
 *
 * @example
 * ```typescript
 * const result = await verifyAccessTokenRequest({
 *   accessTokenRequest: parsedRequest,
 *   authorizationServerMetadata: metadata,
 *   callbacks: { hash, verifyJwt },
 *   clientAttestation: { jwt: "...", popJwt: "..." },
 *   codeExpiresAt: new Date(Date.now() + 600000),
 *   dpop: { jwt: dpopJwt, allowedSigningAlgs: ["ES256"] },
 *   expectedCode: "auth_code_123",
 *   grant: parsedGrant,
 *   pkce: { codeChallenge, codeChallengeMethod: "S256", codeVerifier },
 *   request: httpRequest,
 * });
 * ```
 */
export async function verifyAccessTokenRequest(
  options: VerifyAccessTokenRequestOptions,
): Promise<VerifyAccessTokenRequestResult> {
  await verifyPkce({
    callbacks: options.callbacks,
    codeChallenge: options.pkce.codeChallenge,
    codeChallengeMethod: options.pkce.codeChallengeMethod,
    codeVerifier: options.pkce.codeVerifier,
  });

  const { header, jwkThumbprint } = await verifyTokenDPoP({
    allowedSigningAlgs: options.dpop.allowedSigningAlgs,
    callbacks: options.callbacks,
    dpopJwt: options.dpop.jwt,
    now: options.now,
    request: options.request,
  });

  const clientAttestationResult = await verifyClientAttestation({
    authorizationServerMetadata: options.authorizationServerMetadata,
    callbacks: options.callbacks,
    clientAttestation: options.clientAttestation,
    dpopJwkThumbprint: jwkThumbprint,
    now: options.now,
  });

  if (options.grant.code !== options.expectedCode) {
    throw new Oauth2Error(`Invalid 'code' provided`);
  }

  if (options.codeExpiresAt) {
    const now = options.now ?? new Date();

    if (now.getTime() > options.codeExpiresAt.getTime()) {
      throw new Oauth2Error(`Expired 'code' provided`);
    }
  }

  return {
    clientAttestation: clientAttestationResult,
    dpop: { jwk: header.jwk, jwkThumbprint },
  };
}
