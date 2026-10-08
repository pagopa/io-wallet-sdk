import { BaseRetrieveAccessTokenOptions } from "../create-token-request";
import { AuthorizationCodeGrantType } from "../z-token";
import { PreAuthorizedCodeGrantIdentifier } from "./z-grant-types";
import { PreAuthorizedCodeGrantType } from "./z-token";

export interface RetrieveAccessTokenOptionsAPTITUDE extends BaseRetrieveAccessTokenOptions {
  /** The pre_authorized_code grant type. */
  grantType: PreAuthorizedCodeGrantIdentifier;

  /** The pre-authorized code received in the credential offer. */
  preAuthorizedCode: string;

  /** Required when the credential offer contains a tx_code object. */
  txCode?: string;
}

export type CreateTokenRequestReturnType =
  | AuthorizationCodeGrantType
  | PreAuthorizedCodeGrantType;
