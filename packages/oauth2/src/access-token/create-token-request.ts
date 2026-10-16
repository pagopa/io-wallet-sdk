import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  createVersionDispatcher,
} from "@pagopa/io-wallet-utils";

import {
  AuthorizationCodeGrantIdentifier,
  PreAuthorizedCodeGrantIdentifier,
  RefreshTokenGrantIdentifier,
  authorizationCodeGrantIdentifier,
  preAuthorizedCodeGrantIdentifier,
  refreshTokenGrantIdentifier,
} from "./z-grant-type";
import {
  AuthorizationCodeGrantType,
  PreAuthorizedCodeGrantType,
  RefreshTokenGrantType,
} from "./z-token";

export interface BaseRetrieveAccessTokenOptions {
  /**
   * Additional payload to include in the access token request. Items are encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) are stringified and url encoded.
   * Can be used to include form fields such as client_id or authorization_details.
   */
  additionalRequestPayload?: Record<string, unknown>;

  config: IoWalletSdkConfig;
}

export interface RetrieveAccessTokenOptionsAuthCode<
  V extends ItWalletSpecsVersion,
> extends BaseRetrieveAccessTokenOptions {
  /**
   * The authorization code
   */
  authorizationCode: string;

  config: IoWalletSdkConfig<V>;

  /** The authorization_code grant type. */
  grantType: AuthorizationCodeGrantIdentifier;

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

export interface RetrieveAccessTokenOptionsPreAuthorizedCode extends BaseRetrieveAccessTokenOptions {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.APTITUDE>;

  /** The pre_authorized_code grant type. */
  grantType: PreAuthorizedCodeGrantIdentifier;

  /** The pre-authorized code received in the credential offer. */
  preAuthorizedCode: string;

  /** Required when the credential offer contains a tx_code object. */
  txCode?: string;
}

export interface RetrieveAccessTokenOptionsRefreshToken<
  V extends ItWalletSpecsVersion,
> extends BaseRetrieveAccessTokenOptions {
  config: IoWalletSdkConfig<V>;

  /** The refresh_token grant type. */
  grantType: RefreshTokenGrantIdentifier;

  /** The refresh token received in the credential offer. */
  refreshToken: string;

  /** The refresh token OPTIONAL scope. */
  scope?: string;
}

export type RetrieveAccessTokenOptionsShared<V extends ItWalletSpecsVersion> =
  | RetrieveAccessTokenOptionsAuthCode<V>
  | RetrieveAccessTokenOptionsRefreshToken<V>;

export type RetrieveAccessTokenOptions = RetrieveAccessTokenOptionsShared<
  | ItWalletSpecsVersion.V1_0
  | ItWalletSpecsVersion.V1_3
  | ItWalletSpecsVersion.V1_4
>;

export type RetrieveAccessTokenOptionsAPTITUDE =
  | RetrieveAccessTokenOptionsPreAuthorizedCode
  | RetrieveAccessTokenOptionsShared<ItWalletSpecsVersion.APTITUDE>;

export type CreateTokenRequestOptions =
  | RetrieveAccessTokenOptions
  | RetrieveAccessTokenOptionsAPTITUDE;

export type CreateTokenRequestReturnType =
  | AuthorizationCodeGrantType
  | PreAuthorizedCodeGrantType
  | RefreshTokenGrantType;

export const createTokenRequestV1_4 = <V extends ItWalletSpecsVersion>(
  options: RetrieveAccessTokenOptionsShared<V>,
) => {
  if (options.grantType === refreshTokenGrantIdentifier) {
    return {
      ...options.additionalRequestPayload,
      grant_type: refreshTokenGrantIdentifier,
      refresh_token: options.refreshToken,
      scope: options.scope,
    };
  }

  return {
    ...options.additionalRequestPayload,
    code: options.authorizationCode,
    code_verifier: options.pkceCodeVerifier,
    grant_type: authorizationCodeGrantIdentifier,
    redirect_uri: options.redirectUri,
  };
};

export function createTokenRequestAPTITUDE(
  options: RetrieveAccessTokenOptionsAPTITUDE,
): CreateTokenRequestReturnType {
  if (options.grantType === preAuthorizedCodeGrantIdentifier) {
    return {
      ...options.additionalRequestPayload,
      grant_type: preAuthorizedCodeGrantIdentifier,
      "pre-authorized_code": options.preAuthorizedCode,
      tx_code: options.txCode,
    };
  }

  return createTokenRequestV1_4(options);
}

const dispatchCreateTokenRequest = createVersionDispatcher<
  CreateTokenRequestOptions,
  CreateTokenRequestReturnType
>({
  [ItWalletSpecsVersion.APTITUDE]: (o) =>
    createTokenRequestAPTITUDE(o as RetrieveAccessTokenOptionsAPTITUDE),
  [ItWalletSpecsVersion.V1_0]: (o) =>
    createTokenRequestV1_4(o as RetrieveAccessTokenOptions),
  [ItWalletSpecsVersion.V1_3]: (o) =>
    createTokenRequestV1_4(o as RetrieveAccessTokenOptions),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    createTokenRequestV1_4(o as RetrieveAccessTokenOptions),
});

/**
 * Creates an authorization-code or pre-authorized_code access token request body.
 *
 * Authorization-code requests retain the existing default grant and require PKCE
 * and a redirect URI.
 *
 *  * * Version Differences:
 * - v1.4: only support authorization_code grant type.
 * - APTITUDE: add support for pre-authorized_code grant type. Pre Authorized
 *   requests use preAuthorizedCode and optional txCode, without PKCE or a redirect URI.
 *
 * @param options - Access token request inputs and version config.
 * @param options.config - The IoWalletSdkConfig instance to use.
 * @param options.grantType - The grant type to use.
 * @param options.additionalRequestPayload - Extra form fields to include in the token request.
 *
 * **authorization_code grant type parameters:**
 * @param options.authorizationCode - Authorization code received from the authorization response.
 * @param options.pkceCodeVerifier - PKCE verifier associated with the authorization request.
 * @param options.redirectUri - Redirect URI used in the authorization request.
 *
 * **refresh_token grant type parameters (APTITUDE only):**
 * @param options.refreshToken - Refresh token.
 * @param options.scope - The refresh token OPTIONAL scope.
 *
 * **pre-authorized_code grant type parameters (APTITUDE only):**
 * @param options.preAuthorizedCode - Pre-authorized code received in the credential offer.
 * @param options.txCode - Transaction code required when the credential offer contains a `tx_code` object.
 *
 * @returns URL-form-encodable grant request data.
 */
export function createTokenRequest(
  options: RetrieveAccessTokenOptions,
): AuthorizationCodeGrantType | RefreshTokenGrantType;

export function createTokenRequest(
  options: RetrieveAccessTokenOptionsAPTITUDE,
):
  | AuthorizationCodeGrantType
  | PreAuthorizedCodeGrantType
  | RefreshTokenGrantType;

export function createTokenRequest(
  options: CreateTokenRequestOptions,
): CreateTokenRequestReturnType;

export function createTokenRequest(
  options: CreateTokenRequestOptions,
): CreateTokenRequestReturnType {
  return dispatchCreateTokenRequest(options);
}
