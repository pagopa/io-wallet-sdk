import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { BaseFetchTokenResponseOptions } from "../fetch-token-response";
import { AccessTokenRequestAPTITUDE } from "./z-token";

export interface FetchTokenResponseOptionsAPTITUDE extends BaseFetchTokenResponseOptions {
  /**
   * The authorization-code, pre-authorized-code or refresh-token request payload.
   */
  accessTokenRequest: AccessTokenRequestAPTITUDE;

  config: IoWalletSdkConfig<ItWalletSpecsVersion.APTITUDE>;
}
