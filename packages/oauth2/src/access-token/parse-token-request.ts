import {
  FetchHeaders,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  RequestLike,
  createVersionDispatcher,
  formatZodError,
} from "@pagopa/io-wallet-utils";

import { extractClientAttestationJwtsFromHeaders } from "../client-attestation/wallet-attestation";
import { Oauth2Error } from "../errors";
import { extractDpopJwtFromHeaders } from "../token-dpop/create-token-dpop";
import {
  ParseAccessTokenRequestOptionsAPTITUDE,
  ParseAccessTokenRequestResultAPTITUDE,
  ParsedAccessTokenRequestGrantAPTITUDE,
} from "./APTITUDE/parse-token-request";
import { preAuthorizedCodeGrantIdentifier } from "./APTITUDE/z-grant-types";
import {
  AccessTokenRequestAPTITUDE,
  zAccessTokenRequestAPTITUDE,
} from "./APTITUDE/z-token";
import {
  AuthorizationCodeGrantIdentifier,
  RefreshTokenGrantIdentifier,
  authorizationCodeGrantIdentifier,
  refreshTokenGrantIdentifier,
} from "./z-grant-type";
import { AccessTokenRequest, zAccessTokenRequest } from "./z-token";

export interface ParsedAccessTokenAuthorizationCodeRequestGrant {
  code: string;
  grantType: AuthorizationCodeGrantIdentifier;
}

export interface ParsedAccessTokenRefreshTokenRequestGrant {
  grantType: RefreshTokenGrantIdentifier;
  refreshToken: string;
}

export type ParsedAccessTokenRequestGrant =
  | ParsedAccessTokenAuthorizationCodeRequestGrant
  | ParsedAccessTokenRefreshTokenRequestGrant;

export interface BaseParseAccessTokenRequestResult {
  /**
   * The client attestation jwts from the access token request headers
   */
  clientAttestation: {
    clientAttestationPopJwt: string;
    walletAttestationJwt: string;
  };

  /**
   * The dpop jwt from the access token request headers
   */
  dpop: {
    jwt: string;
  };
}

export interface ParseAccessTokenRequestResultV1_4 extends BaseParseAccessTokenRequestResult {
  accessTokenRequest: AccessTokenRequest;

  grant: ParsedAccessTokenRequestGrant;

  /**
   * The pkce code verifier from the access token request
   */
  pkceCodeVerifier?: string;
}

export interface ParseAccessTokenRequestOptions {
  /**
   * The access token request as a JSON object. Your server should decode the
   * `x-www-url-form-urlencoded` body into an object (e.g. using `bodyParser.urlEncoded()` in express)
   */
  accessTokenRequest: Record<string, unknown>;

  config: IoWalletSdkConfig;

  request: RequestLike;
}

export interface ParseAccessTokenRequestOptionsV1_4 extends ParseAccessTokenRequestOptions {
  /**
   * The IT-Wallet specs version to use for parsing the access token request.
   */
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
}

export type ParseAccessTokenRequestResult =
  | ParseAccessTokenRequestResultAPTITUDE
  | ParseAccessTokenRequestResultV1_4;

function parseAccessTokenRequestV1_4(
  options: ParseAccessTokenRequestOptionsV1_4,
): ParseAccessTokenRequestResultV1_4 {
  const validationResult = zAccessTokenRequest.safeParse(
    options.accessTokenRequest,
  );

  if (!validationResult.success) {
    throw new Oauth2Error(
      `Access token request validation failed:\n${formatZodError(validationResult.error)}`,
    );
  }

  const accessTokenRequest = validationResult.data;
  const grant = parseGrantParameters(accessTokenRequest);
  const securityHeaders = parseSecurityHeaders(options.request.headers);
  const pkceCodeVerifier =
    accessTokenRequest.grant_type === "authorization_code"
      ? accessTokenRequest.code_verifier
      : undefined;

  return {
    accessTokenRequest,
    grant,
    pkceCodeVerifier,
    ...securityHeaders,
  };
}

function parseAccessTokenRequestAPTITUDE(
  options: ParseAccessTokenRequestOptionsAPTITUDE,
): ParseAccessTokenRequestResultAPTITUDE {
  const validationResult = zAccessTokenRequestAPTITUDE.safeParse(
    options.accessTokenRequest,
  );

  if (!validationResult.success) {
    throw new Oauth2Error(
      `Access token request validation failed:\n${formatZodError(validationResult.error)}`,
    );
  }

  const accessTokenRequest = validationResult.data;
  const grant = parseGrantParametersAPTITUDE(accessTokenRequest);
  const securityHeaders = parseSecurityHeaders(options.request.headers);

  return {
    accessTokenRequest,
    grant,
    ...securityHeaders,
  };
}

/**
 * Parses the grant-specific parameters from an access token request.
 *
 * Validates that the required parameters for the grant type are present
 * and returns a typed grant object.
 *
 * @param accessTokenRequest - The validated access token request
 * @returns Typed grant object containing grant-specific parameters
 * @throws {Oauth2Error} If required grant parameters are missing or grant type is unsupported
 */
function parseGrantParameters(
  accessTokenRequest: AccessTokenRequest,
): ParsedAccessTokenRequestGrant {
  if (accessTokenRequest.grant_type === authorizationCodeGrantIdentifier) {
    return {
      code: accessTokenRequest.code,
      grantType: authorizationCodeGrantIdentifier,
    };
  }

  if (accessTokenRequest.grant_type === refreshTokenGrantIdentifier) {
    return {
      grantType: refreshTokenGrantIdentifier,
      refreshToken: accessTokenRequest.refresh_token,
    };
  }

  throw new Oauth2Error(
    `Unsupported grant type. Supported types are: '${authorizationCodeGrantIdentifier}', '${refreshTokenGrantIdentifier}'`,
  );
}

/**
 * Parses the grant-specific parameters from an access token request.
 *
 * Validates that the required parameters for the grant type are present
 * and returns a typed grant object.
 *
 * @param accessTokenRequest - The validated access token request
 * @returns Typed grant object containing grant-specific parameters
 * @throws {Oauth2Error} If required grant parameters are missing or grant type is unsupported
 */
function parseGrantParametersAPTITUDE(
  accessTokenRequest: AccessTokenRequestAPTITUDE,
): ParsedAccessTokenRequestGrantAPTITUDE {
  if (accessTokenRequest.grant_type === authorizationCodeGrantIdentifier) {
    return {
      code: accessTokenRequest.code,
      grantType: authorizationCodeGrantIdentifier,
    };
  }

  if (accessTokenRequest.grant_type === refreshTokenGrantIdentifier) {
    return {
      grantType: refreshTokenGrantIdentifier,
      refreshToken: accessTokenRequest.refresh_token,
    };
  }

  if (accessTokenRequest.grant_type === preAuthorizedCodeGrantIdentifier) {
    return {
      grantType: preAuthorizedCodeGrantIdentifier,
      preAuthorizedCode: accessTokenRequest["pre-authorized_code"],
      txCode: accessTokenRequest.tx_code,
    };
  }

  throw new Oauth2Error(
    `Unsupported grant type. Supported types are: '${authorizationCodeGrantIdentifier}', '${refreshTokenGrantIdentifier}', '${preAuthorizedCodeGrantIdentifier}'`,
  );
}

/**
 * Extracts and validates security headers (DPoP and Client Attestation) from the request.
 *
 * This function only parses the headers without verifying the cryptographic signatures.
 * Signature verification should be performed separately.
 *
 * @param headers - The HTTP request headers
 * @returns Object containing extracted DPoP JWT and Client Attestation JWTs if present
 * @throws {Oauth2Error} If headers are present but malformed
 */
function parseSecurityHeaders(headers: FetchHeaders) {
  const extractedDpopJwt = extractDpopJwtFromHeaders(headers);
  if (!extractedDpopJwt.valid) {
    throw new Oauth2Error(
      "Request contains a 'DPoP' header, but the value is not a valid JWT format",
    );
  }

  if (!extractedDpopJwt.dpopJwt) {
    throw new Oauth2Error("Request is missing required 'DPoP' header");
  }

  const extractedClientAttestationJwts =
    extractClientAttestationJwtsFromHeaders(headers);

  if (!extractedClientAttestationJwts.valid) {
    throw new Oauth2Error(
      "Request contains client attestation headers, but the values are not in valid JWT format",
    );
  }

  if (!extractedClientAttestationJwts.walletAttestationHeader) {
    throw new Oauth2Error(
      "Request is missing required 'OAuth-Client-Attestation' header",
    );
  }

  if (!extractedClientAttestationJwts.clientAttestationPopHeader) {
    throw new Oauth2Error(
      "Request is missing required 'OAuth-Client-Attestation-PoP' header",
    );
  }

  return {
    clientAttestation: {
      clientAttestationPopJwt:
        extractedClientAttestationJwts.clientAttestationPopHeader,
      walletAttestationJwt:
        extractedClientAttestationJwts.walletAttestationHeader,
    },
    dpop: { jwt: extractedDpopJwt.dpopJwt },
  };
}

const dispatchParseTokenRequest = createVersionDispatcher<
  ParseAccessTokenRequestOptions,
  ParseAccessTokenRequestResult
>({
  [ItWalletSpecsVersion.APTITUDE]: (o) =>
    parseAccessTokenRequestAPTITUDE(
      o as ParseAccessTokenRequestOptionsAPTITUDE,
    ),
  [ItWalletSpecsVersion.V1_0]: (o) =>
    parseAccessTokenRequestV1_4(o as ParseAccessTokenRequestOptionsV1_4),
  [ItWalletSpecsVersion.V1_3]: (o) =>
    parseAccessTokenRequestV1_4(o as ParseAccessTokenRequestOptionsV1_4),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    parseAccessTokenRequestV1_4(o as ParseAccessTokenRequestOptionsV1_4),
});

/**
 * Parses and validates an OAuth 2.0 access token request.
 *
 * This function performs the following steps:
 * 1. Validates the request body against the access token request schema
 * 2. Extracts grant parameters for authorization code, pre-authorized code or refresh token
 * 3. Parses security headers (DPoP and Client Attestation JWTs)
 * 4. Extracts PKCE code verifier if present (V1_4 only)
 *
 * Note: This function only parses and validates the structure of the request.
 * Cryptographic verification of JWTs and tokens should be performed separately.
 *
 * * * Version Differences:
 * - APTITUDE: add support for pre-authorized-code grant type.
 *
 * @param options - Configuration object containing the access token request body and HTTP request, and version config
 * @returns Parsed access token request with typed grant parameters and extracted security headers
 * @throws {Oauth2Error} If validation fails or required parameters are missing
 *
 * @example
 * ```typescript
 * const result = parseAccessTokenRequest({
 *   accessTokenRequest: {
 *     grant_type: 'authorization_code',
 *     code: 'auth_code_123',
 *     client_id: 'client_123',
 *     code_verifier: 'verifier_xyz'
 *   },
 *   request: httpRequest
 * });
 * ```
 */
export function parseAccessTokenRequest(
  options: ParseAccessTokenRequestOptionsV1_4,
): ParseAccessTokenRequestResultV1_4;

export function parseAccessTokenRequest(
  options: ParseAccessTokenRequestOptionsAPTITUDE,
): ParseAccessTokenRequestResultAPTITUDE;

export function parseAccessTokenRequest(
  options: ParseAccessTokenRequestOptions,
): ParseAccessTokenRequestResult;

export function parseAccessTokenRequest(
  options: ParseAccessTokenRequestOptions,
): ParseAccessTokenRequestResult {
  return dispatchParseTokenRequest(options);
}
