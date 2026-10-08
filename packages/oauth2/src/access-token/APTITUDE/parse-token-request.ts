import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import {
  BaseParseAccessTokenRequestResult,
  ParseAccessTokenRequestOptions,
  ParsedAccessTokenAuthorizationCodeRequestGrant,
  ParsedAccessTokenRefreshTokenRequestGrant,
} from "../parse-token-request";
import { PreAuthorizedCodeGrantIdentifier } from "./z-grant-types";
import { AccessTokenRequestAPTITUDE } from "./z-token";

export interface ParsedAccessTokenPreAuthorizedCodeRequestGrant {
  grantType: PreAuthorizedCodeGrantIdentifier;
  preAuthorizedCode: string;
  txCode?: string;
}

export interface ParseAccessTokenRequestResultAPTITUDE extends BaseParseAccessTokenRequestResult {
  accessTokenRequest: AccessTokenRequestAPTITUDE;

  grant: ParsedAccessTokenRequestGrantAPTITUDE;
}

export interface ParseAccessTokenRequestOptionsAPTITUDE extends ParseAccessTokenRequestOptions {
  /**
   * The IT-Wallet specs version to use for parsing the access token request.
   */
  config: IoWalletSdkConfig<ItWalletSpecsVersion.APTITUDE>;
}

export type ParsedAccessTokenRequestGrantAPTITUDE =
  | ParsedAccessTokenAuthorizationCodeRequestGrant
  | ParsedAccessTokenPreAuthorizedCodeRequestGrant
  | ParsedAccessTokenRefreshTokenRequestGrant;
