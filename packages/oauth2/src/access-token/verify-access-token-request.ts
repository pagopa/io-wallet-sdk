import type { ItWalletAuthorizationServerMetadata } from "@pagopa/io-wallet-oid-federation";

import { CallbackContext } from "@openid4vc/oauth2";
import { IoWalletSdkConfig, RequestLike } from "@pagopa/io-wallet-utils";

import { VerifiedClientAttestationPopJwt } from "../client-attestation/client-attestation-pop";
import {
  ClientAttestationOptions,
  verifyClientAttestation,
} from "../client-attestation/verify-client-attestation";
import { VerifiedWalletAttestationJwt } from "../client-attestation/wallet-attestation";
import { Jwk } from "../common/jwk/z-jwk";
import { Oauth2Error } from "../errors";
import { PkceCodeChallengeMethod, verifyPkce } from "../pkce";
import { verifyTokenDPoP } from "../token-dpop/verify-token-dpop";
import {
  ParsedAccessTokenAuthorizationCodeRequestGrant,
  ParsedAccessTokenPreAuthorizedCodeRequestGrant,
} from "./parse-token-request";
import {
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from "./z-grant-type";
import { AccessTokenRequest, PreAuthorizedCodeGrantType } from "./z-token";

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
   * The expected DPoP nonce value that must appear in the `nonce` claim of the DPoP proof JWT.
   *
   * AS implementations **SHOULD** issue server-provided nonces (via the `DPoP-Nonce` response
   * header) and pass the expected value here to prevent pre-generated DPoP proofs from being
   * reused across requests within the `iat` window.
   *
   * See RFC 9449 §8 for the full nonce issuance flow.
   */
  expectedNonce?: string;

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
  authorizationServerMetadata: ItWalletAuthorizationServerMetadata;

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

  config: IoWalletSdkConfig;

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
   * The current time to use when verifying the JWTs.
   * If not provided current time will be used.
   *
   * @default new Date()
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

export interface VerifyPreAuthorizedCodeAccessTokenRequestOptions extends Omit<
  VerifyAccessTokenRequestOptions,
  "accessTokenRequest" | "codeExpiresAt" | "expectedCode" | "grant" | "pkce"
> {
  accessTokenRequest: PreAuthorizedCodeGrantType;

  /** The pre-authorized code stored by the authorization server. */
  expectedPreAuthorizedCode: string;

  /** The stored transaction code, if one was required by the credential offer. */
  expectedTxCode?: string;

  /** The parsed pre-authorized code grant */
  grant: ParsedAccessTokenPreAuthorizedCodeRequestGrant;

  /** The expiration date stored with the pre-authorized code. */
  preAuthorizedCodeExpiresAt?: Date;
}

type SupportedAccessTokenVerificationOptions =
  | VerifyAccessTokenRequestOptions
  | VerifyPreAuthorizedCodeAccessTokenRequestOptions;

export interface VerifyAccessTokenRequestResult {
  clientAttestation: {
    clientAttestation: VerifiedWalletAttestationJwt;
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
 * Verifies an authorization-code or pre-authorized-code token request.
 *
 * Both grants retain the SDK's IT-Wallet DPoP and client attestation requirements:
 * - PKCE verification against the stored code challenge for authorization-code requests only
 * - DPoP proof JWT verification and JWK thumbprint extraction
 * - Client attestation JWT and attestation PoP JWT verification
 * - Authorization code or pre-authorized code validity and expiration checks
 * - Transaction code verification when required by the credential offer
 *
 * The caller must enforce single-use redemption of codes atomically when issuing
 * the token, and limit transaction-code attempts. This verifier does not store state.
 * The upstream verifier allows optional DPoP and client attestation; the local
 * implementation retains the SDK's required security checks and error types.
 *
 * @param options - Configuration options for token request verification
 * @returns A promise that resolves with verified client attestation and DPoP information
 * @throws {Oauth2Error} If the grant code is invalid or expired, or the transaction code is missing, unexpected or invalid
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
 *   dpop: {
 *     allowedSigningAlgs: ["ES256"],
 *     expectedNonce: "server-issued-nonce",
 *     jwt: dpopJwt,
 *   },
 *   expectedCode: "auth_code_123",
 *   grant: parsedGrant,
 *   pkce: { codeChallenge, codeChallengeMethod: "S256", codeVerifier },
 *   request: httpRequest,
 * });
 * ```
 */
export async function verifyAccessTokenRequest(
  options: SupportedAccessTokenVerificationOptions,
): Promise<VerifyAccessTokenRequestResult> {
  if (options.dpop.expectedNonce === "") {
    throw new Oauth2Error(`Invalid 'dpop.expectedNonce' provided`);
  }

  if (!isPreAuthorizedCodeVerification(options)) {
    await verifyPkce({
      callbacks: options.callbacks,
      codeChallenge: options.pkce.codeChallenge,
      codeChallengeMethod: options.pkce.codeChallengeMethod,
      codeVerifier: options.pkce.codeVerifier,
    });
  }

  const { header, jwkThumbprint } = await verifyTokenDPoP({
    allowedSigningAlgs: options.dpop.allowedSigningAlgs,
    callbacks: options.callbacks,
    dpopJwt: options.dpop.jwt,
    expectedNonce: options.dpop.expectedNonce,
    now: options.now,
    request: options.request,
  });

  const clientAttestationResult = await verifyClientAttestation({
    authorizationServerMetadata: options.authorizationServerMetadata,
    callbacks: options.callbacks,
    clientAttestation: options.clientAttestation,
    config: options.config,
    dpopJwkThumbprint: jwkThumbprint,
    now: options.now,
  });

  verifyGrantParameters(options);

  if (!header.jwk) {
    throw new Oauth2Error("DPoP header does not contain a JWK");
  }

  return {
    clientAttestation: clientAttestationResult,
    dpop: { jwk: header.jwk, jwkThumbprint },
  };
}

function isPreAuthorizedCodeVerification(
  options: SupportedAccessTokenVerificationOptions,
): options is VerifyPreAuthorizedCodeAccessTokenRequestOptions {
  return options.grant.grantType === preAuthorizedCodeGrantIdentifier;
}

function verifyGrantParameters(
  options: SupportedAccessTokenVerificationOptions,
) {
  if (options.accessTokenRequest.grant_type !== options.grant.grantType) {
    throw new Oauth2Error("Grant type does not match the access token request");
  }

  if (isPreAuthorizedCodeVerification(options)) {
    if (
      !options.expectedPreAuthorizedCode ||
      options.grant.preAuthorizedCode !== options.expectedPreAuthorizedCode ||
      options.accessTokenRequest["pre-authorized_code"] !==
        options.grant.preAuthorizedCode
    ) {
      throw new Oauth2Error(`Invalid 'pre-authorized_code' provided`);
    }

    if (options.accessTokenRequest.tx_code !== options.grant.txCode) {
      throw new Oauth2Error(
        "Transaction code does not match the access token request",
      );
    }
    verifyTransactionCode(options.grant.txCode, options.expectedTxCode);
    verifyCodeExpiration(
      options.preAuthorizedCodeExpiresAt,
      options.now,
      "pre-authorized_code",
    );
    return;
  }

  if (
    options.accessTokenRequest.grant_type !== authorizationCodeGrantIdentifier
  ) {
    throw new Oauth2Error(
      "Only authorization_code and pre-authorized_code grants can be verified",
    );
  }

  if (
    !options.expectedCode ||
    options.grant.code !== options.expectedCode ||
    options.accessTokenRequest.code !== options.grant.code
  ) {
    throw new Oauth2Error(`Invalid 'code' provided`);
  }
  verifyCodeExpiration(options.codeExpiresAt, options.now, "code");
}

function verifyTransactionCode(
  txCode: string | undefined,
  expectedTxCode: string | undefined,
) {
  if (txCode === expectedTxCode) return;

  if (expectedTxCode === undefined) {
    throw new Oauth2Error("Request contains 'tx_code' that was not expected");
  }

  if (txCode === undefined) {
    throw new Oauth2Error("Missing required 'tx_code' in request");
  }

  throw new Oauth2Error("Invalid 'tx_code' provided");
}

function verifyCodeExpiration(
  expiresAt: Date | undefined,
  date: Date | undefined,
  codeParameter: string,
) {
  if (!expiresAt) return;

  if (Number.isNaN(expiresAt.getTime())) {
    throw new Oauth2Error(`Invalid expiration date for '${codeParameter}'`);
  }

  const now = date ?? new Date();

  if (now.getTime() > expiresAt.getTime()) {
    throw new Oauth2Error(`Expired '${codeParameter}' provided`);
  }
}
