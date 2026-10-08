import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  createVersionDispatcher,
} from "@pagopa/io-wallet-utils";

import {
  CreateTokenRequestReturnType,
  RetrieveAccessTokenOptionsAPTITUDE,
} from "./APTITUDE/create-token-request";
import { preAuthorizedCodeGrantIdentifier } from "./APTITUDE/z-grant-types";
import { PreAuthorizedCodeGrantType } from "./APTITUDE/z-token";
import {
  AuthorizationCodeGrantIdentifier,
  authorizationCodeGrantIdentifier,
} from "./z-grant-type";
import { AuthorizationCodeGrantType } from "./z-token";

export interface BaseRetrieveAccessTokenOptions {
  /**
   * Additional payload to include in the access token request. Items are encoded and sent
   * using x-www-form-urlencoded format. Nested items (JSON) are stringified and url encoded.
   * Can be used to include form fields such as client_id or authorization_details.
   */
  additionalRequestPayload?: Record<string, unknown>;

  config: IoWalletSdkConfig;
}

export interface RetrieveAccessTokenOptionsV1_4 extends BaseRetrieveAccessTokenOptions {
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

export type CreateTokenRequestOptions =
  | RetrieveAccessTokenOptionsAPTITUDE
  | RetrieveAccessTokenOptionsV1_4;

export const createTokenRequestV1_4 = (
  options: RetrieveAccessTokenOptionsV1_4,
) =>
  ({
    ...options.additionalRequestPayload,
    code: options.authorizationCode,
    code_verifier: options.pkceCodeVerifier,
    grant_type: authorizationCodeGrantIdentifier,
    redirect_uri: options.redirectUri,
  }) satisfies AuthorizationCodeGrantType;

export function createTokenRequestAPTITUDE(
  options: RetrieveAccessTokenOptionsAPTITUDE | RetrieveAccessTokenOptionsV1_4,
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
    createTokenRequestAPTITUDE(o as CreateTokenRequestOptions),
  [ItWalletSpecsVersion.V1_0]: (o) =>
    createTokenRequestV1_4(o as RetrieveAccessTokenOptionsV1_4),
  [ItWalletSpecsVersion.V1_3]: (o) =>
    createTokenRequestV1_4(o as RetrieveAccessTokenOptionsV1_4),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    createTokenRequestV1_4(o as RetrieveAccessTokenOptionsV1_4),
});

/**
 * Creates an authorization-code or pre-authorized-code access token request body.
 *
 * Authorization-code requests retain the existing default grant and require PKCE
 * and a redirect URI.
 *
 * - APTITUDE: this version differs for support of Pre-Authorized Code grant.
 * Pre-authorized requests use preAuthorizedCode and optional
 * txCode, without PKCE or a redirect URI.
 *
 * @param options - Access token request inputs and version config.
 * @param options.additionalRequestPayload - Extra form fields to include in the token request.
 * @returns URL-form-encodable grant request data.
 */
export function createTokenRequest(
  options: RetrieveAccessTokenOptionsV1_4,
): AuthorizationCodeGrantType;

export function createTokenRequest(
  options: RetrieveAccessTokenOptionsAPTITUDE,
): AuthorizationCodeGrantType | PreAuthorizedCodeGrantType;

export function createTokenRequest(
  options: CreateTokenRequestOptions,
): CreateTokenRequestReturnType;

export function createTokenRequest(
  options: CreateTokenRequestOptions,
): CreateTokenRequestReturnType {
  return dispatchCreateTokenRequest(options);
}
