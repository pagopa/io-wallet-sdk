import {
  FetchHeaders,
  RequestLike,
  formatZodError,
} from "@pagopa/io-wallet-utils";

import { extractClientAttestationJwtsFromHeaders } from "../client-attestation";
import { Oauth2Error } from "../errors";
import { extractDpopJwtFromHeaders } from "../token-dpop";
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

type ParsedAccessTokenRequestGrant =
  | ParsedAccessTokenAuthorizationCodeRequestGrant
  | ParsedAccessTokenRefreshTokenRequestGrant;

export interface ParseAccessTokenRequestResult {
  accessTokenRequest: AccessTokenRequest;
  /**
   * The client attestation jwts from the access token request headers
   */
  clientAttestation?: {
    clientAttestationJwt: string;
    clientAttestationPopJwt: string;
  };

  /**
   * The dpop jwt from the access token request headers
   */
  dpop?: {
    jwt: string;
  };

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

  request: RequestLike;
}

/**
 * Parses and validates an OAuth 2.0 access token request.
 *
 * This function performs the following steps:
 * 1. Validates the request body against the access token request schema
 * 2. Extracts and validates grant-specific parameters (authorization code or refresh token)
 * 3. Parses security headers (DPoP and Client Attestation JWTs)
 * 4. Extracts PKCE code verifier if present
 *
 * Note: This function only parses and validates the structure of the request.
 * Cryptographic verification of JWTs and tokens should be performed separately.
 *
 * @param options - Configuration object containing the access token request body and HTTP request
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
  options: ParseAccessTokenRequestOptions,
): ParseAccessTokenRequestResult {
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
  const pkceCodeVerifier = accessTokenRequest.code_verifier;

  return {
    accessTokenRequest,
    grant,
    pkceCodeVerifier,
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
  const { code, grant_type, refresh_token } = accessTokenRequest;

  if (grant_type === authorizationCodeGrantIdentifier) {
    if (!code) {
      throw new Oauth2Error(
        `Missing required 'code' parameter for grant type '${authorizationCodeGrantIdentifier}'`,
      );
    }

    return {
      code,
      grantType: authorizationCodeGrantIdentifier,
    };
  }

  if (grant_type === refreshTokenGrantIdentifier) {
    if (!refresh_token) {
      throw new Oauth2Error(
        `Missing required 'refresh_token' parameter for grant type '${refreshTokenGrantIdentifier}'`,
      );
    }

    return {
      grantType: refreshTokenGrantIdentifier,
      refreshToken: refresh_token,
    };
  }

  throw new Oauth2Error(
    `Unsupported grant type '${grant_type}'. Supported types are: '${authorizationCodeGrantIdentifier}', '${refreshTokenGrantIdentifier}'`,
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

  const extractedClientAttestationJwts =
    extractClientAttestationJwtsFromHeaders(headers);
  if (!extractedClientAttestationJwts.valid) {
    throw new Oauth2Error(
      "Request contains client attestation headers, but the values are not in valid JWT format",
    );
  }

  return {
    clientAttestation: extractedClientAttestationJwts.clientAttestationHeader
      ? {
          clientAttestationJwt:
            extractedClientAttestationJwts.clientAttestationHeader,
          clientAttestationPopJwt:
            extractedClientAttestationJwts.clientAttestationPopHeader,
        }
      : undefined,
    dpop: extractedDpopJwt.dpopJwt
      ? { jwt: extractedDpopJwt.dpopJwt }
      : undefined,
  };
}
