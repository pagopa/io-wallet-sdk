import { Openid4vpAuthorizationRequestPayload } from "../authorization-request";
import { Oid4vpError } from "../errors";
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
export interface ValidateOpenid4vpAuthorizationResponseResult {
  presentations: ReturnType<typeof parseVpToken>;
  query: Openid4vpAuthorizationRequestPayload["dcql_query"];
}

/**
 * Validates the OpenID4VP authorization response payload against the request payload.
 *
 * @param options {@link ValidateOpenid4vpAuthorizationResponseOptions}
 * @returns Presentations and query extracted from the validated flow.
 * @throws {Oid4vpError} If `state` is present in the request and does not match the response.
 */
export function validateOpenid4vpAuthorizationResponsePayload(
  options: ValidateOpenid4vpAuthorizationResponseOptions,
): ValidateOpenid4vpAuthorizationResponseResult {
  const { authorizationRequestPayload, authorizationResponsePayload } = options;

  if (
    authorizationRequestPayload.state &&
    authorizationRequestPayload.state !== authorizationResponsePayload.state
  ) {
    throw new Oid4vpError("OpenId4Vp Authorization Response state mismatch.");
  }

  const presentations = parseVpToken(authorizationResponsePayload.vp_token);

  return {
    presentations,
    query: authorizationRequestPayload.dcql_query,
  };
}
