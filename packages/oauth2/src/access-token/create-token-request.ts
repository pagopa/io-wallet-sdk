import {
  AuthorizationCodeGrantIdentifier,
  PreAuthorizedCodeGrantIdentifier,
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
} from "./z-grant-type";
import {
  AuthorizationCodeGrantType,
  PreAuthorizedCodeGrantType,
} from "./z-token";

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

  /** The authorization_code grant type. */
  grantType?: AuthorizationCodeGrantIdentifier;

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

export interface RetrievePreAuthorizedCodeAccessTokenOptions {
  /** Additional form fields, such as client_id or authorization_details. */
  additionalRequestPayload?: Record<string, unknown>;

  /** The pre_authorized_code grant type. */
  grantType: PreAuthorizedCodeGrantIdentifier;

  /** The pre-authorized code received in the credential offer. */
  preAuthorizedCode: string;

  /** Required when the credential offer contains a tx_code object. */
  txCode?: string;
}

export type CreateTokenRequestOptions =
  | RetrieveAuthorizationCodeAccessTokenOptions
  | RetrievePreAuthorizedCodeAccessTokenOptions;

/**
 * Creates an authorization-code or pre-authorized-code access token request body.
 *
 * Authorization-code requests retain the existing default grant and require PKCE
 * and a redirect URI. Pre-authorized requests use preAuthorizedCode and optional
 * txCode, without PKCE or a redirect URI.
 *
 * @param options - Access token request inputs.
 * @param options.additionalRequestPayload - Extra form fields to include in the token request.
 * @returns URL-form-encodable grant request data.
 */
export async function createTokenRequest(
  options: CreateTokenRequestOptions,
): Promise<AuthorizationCodeGrantType | PreAuthorizedCodeGrantType> {
  if (options.grantType === preAuthorizedCodeGrantIdentifier) {
    return {
      ...options.additionalRequestPayload,
      grant_type: preAuthorizedCodeGrantIdentifier,
      "pre-authorized_code": options.preAuthorizedCode,
      tx_code: options.txCode,
    };
  }

  return {
    ...options.additionalRequestPayload,
    code: options.authorizationCode,
    code_verifier: options.pkceCodeVerifier,
    grant_type: authorizationCodeGrantIdentifier,
    redirect_uri: options.redirectUri,
  };
}
