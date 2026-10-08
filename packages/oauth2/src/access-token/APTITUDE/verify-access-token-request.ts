import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import {
  BaseVerifyAccessTokenRequestOptions,
  VerifyAccessTokenRequestOptions,
} from "../verify-access-token-request";
import { ParsedAccessTokenPreAuthorizedCodeRequestGrant } from "./parse-token-request";
import { PreAuthorizedCodeGrantType } from "./z-token";

export interface VerifyPreAuthorizedCodeAccessTokenRequestOptions extends BaseVerifyAccessTokenRequestOptions {
  /**
   * The access token request to verify
   */
  accessTokenRequest: PreAuthorizedCodeGrantType;

  config: IoWalletSdkConfig<ItWalletSpecsVersion.APTITUDE>;

  /** The pre-authorized code stored by the authorization server. */
  expectedPreAuthorizedCode: string;

  /** The stored transaction code, if one was required by the credential offer. */
  expectedTxCode?: string;

  /** The parsed pre-authorized code grant */
  grant: ParsedAccessTokenPreAuthorizedCodeRequestGrant;

  /** The expiration date stored with the pre-authorized code. */
  preAuthorizedCodeExpiresAt?: Date;
}

export type SupportedAccessTokenVerificationOptionsAPTITUDE =
  | VerifyAccessTokenRequestOptions
  | VerifyPreAuthorizedCodeAccessTokenRequestOptions;
