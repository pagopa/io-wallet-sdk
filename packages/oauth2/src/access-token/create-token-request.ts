import type { CallbackContext } from "../common/callback-context";

import { AuthorizationCodeGrantType } from "./z-token";

export interface RetrieveAuthorizationCodeAccessTokenOptions {
  /**
   * Additional payload to include in the access token request. Items will be encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) will be stringified and url encoded.
   */
  additionalRequestPayload?: Record<string, unknown>;

  /**
   * The authorization code
   */
  authorizationCode: string;

  /**
   * Callbacks to use for requesting access token
   */
  callbacks: Pick<
    CallbackContext,
    "clientAuthentication" | "fetch" | "generateRandom" | "hash" | "signJwt"
  >;

  /**
   * PKCE Code verifier that was used in the authorization request.
   */
  pkceCodeVerifier: string;

  /**
   * Redirect uri to include in the access token request.
   * It MUST be set as in the Request Object.
   */
  redirectUri: string;
}

/**
 * Creates an OAuth 2.0 authorization-code access token request body.
 *
 * @param options - Access token request inputs.
 * @param options.additionalRequestPayload - Extra form fields to include in the token request.
 * @param options.authorizationCode - Authorization code received from the authorization response.
 * @param options.pkceCodeVerifier - PKCE verifier associated with the authorization request.
 * @param options.redirectUri - Redirect URI used in the authorization request.
 * @returns URL-form-encodable authorization-code grant request data.
 */
export const createTokenRequest = async (
  options: RetrieveAuthorizationCodeAccessTokenOptions,
) =>
  ({
    ...options.additionalRequestPayload,
    code: options.authorizationCode,
    code_verifier: options.pkceCodeVerifier,
    grant_type: "authorization_code",
    redirect_uri: options.redirectUri,
  }) satisfies AuthorizationCodeGrantType;
