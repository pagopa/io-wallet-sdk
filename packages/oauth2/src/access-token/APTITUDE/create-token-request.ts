import {
  BaseRetrieveAccessTokenOptions,
  RetrieveAccessTokenOptionsAuthCode,
} from "../create-token-request";
import { PreAuthorizedCodeGrantIdentifier } from "./z-grant-types";

export interface RetrieveAccessTokenOptionsPreAuthorizedCode extends BaseRetrieveAccessTokenOptions {
  /** The pre_authorized_code grant type. */
  grantType: PreAuthorizedCodeGrantIdentifier;

  /** The pre-authorized code received in the credential offer. */
  preAuthorizedCode: string;

  /** Required when the credential offer contains a tx_code object. */
  txCode?: string;
}

export type RetrieveAccessTokenOptionsAPTITUDE =
  | RetrieveAccessTokenOptionsAuthCode
  | RetrieveAccessTokenOptionsPreAuthorizedCode;
