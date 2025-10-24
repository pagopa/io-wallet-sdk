import { CallbackContext } from "@openid4vc/oauth2";

import { AccessTokenRequest } from "./z-token";

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
  pkceCodeVerifier?: string;

  /**
   * Redirect uri to include in the access token request. Only required
   * if the redirect uri was present in the authorization request.
   */
  redirectUri?: string;
}

export const createTokenRequest = async (
  options: RetrieveAuthorizationCodeAccessTokenOptions,
) =>
  ({
    code: options.authorizationCode,
    code_verifier: options.pkceCodeVerifier,
    grant_type: "authorization_code",
    redirect_uri: options.redirectUri,
    ...options.additionalRequestPayload,
  }) satisfies AccessTokenRequest;
