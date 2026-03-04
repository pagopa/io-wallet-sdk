import { Oauth2Error } from "@openid4vc/oauth2";

import { Openid4vpAuthorizationRequestPayload } from "../authorization-request";
import { parseVpToken } from "../vp-token";
import { Openid4vpAuthorizationResponse } from "./z-authorization-response";

export interface ValidateOpenid4vpAuthorizationResponseOptions {
  /**
   * Parsed request payload used as validation source.
   */
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload;
  /**
   * Parsed authorization response payload to validate.
   */
  authorizationResponsePayload: Openid4vpAuthorizationResponse;
}

/**
 * Result of authorization response validation.
 */
export interface ValidateOpenid4VpAuthorizationResponseResult {
  presentations: ReturnType<typeof parseVpToken>;
  query: Openid4vpAuthorizationRequestPayload["dcql_query"];
}

/**
 * Validates the OpenID4VP authorization response payload against the request payload.
 *
 * @param options {@link ValidateOpenid4vpAuthorizationResponseOptions}
 * @returns Presentations and query extracted from the validated flow.
 * @throws {Oauth2Error} If `state` is present in the request and does not match the response.
 */
export function validateOpenid4vpAuthorizationResponsePayload(
  options: ValidateOpenid4vpAuthorizationResponseOptions,
) {
  const { authorizationRequestPayload, authorizationResponsePayload } = options;

  if (
    authorizationRequestPayload.state &&
    authorizationRequestPayload.state !== authorizationResponsePayload.state
  ) {
    throw new Oauth2Error("OpenId4Vp Authorization Response state mismatch.");
  }

  const presentations = parseVpToken(authorizationResponsePayload.vp_token);

  return {
    presentations,
    query: authorizationRequestPayload.dcql_query,
  };
}
