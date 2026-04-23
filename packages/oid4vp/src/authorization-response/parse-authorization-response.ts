import { CallbackContext } from "@pagopa/io-wallet-oauth2";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import { Openid4vpAuthorizationRequestPayload } from "../authorization-request/z-authorization-request";
import { Oid4vpError } from "../errors";
import { parseJarmAuthorizationResponse } from "../jarm/parse-jarm-authorization-response";
import { VerifyJarmAuthorizationResponseResult } from "../jarm/verify-jarm-authorization-response";
import { JarmHeader } from "../jarm/z-jarm";
import {
  ValidateOpenid4vpAuthorizationResponseResult,
  validateOpenid4vpAuthorizationResponsePayload,
} from "./validate-authorization-response";
import {
  Openid4vpAuthorizationResponse,
  zOpenid4vpAuthorizationResponse,
} from "./z-authorization-response";

export interface ParseAuthorizationResponseOptions {
  /**
   * Parsed authorization request payload used to validate response parameters.
   */
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload;
  /**
   * Authorization response received from the verifier endpoint or redirect URI.
   */
  authorizationResponse: Record<string, unknown>;
  /**
   * Callbacks required when the response is returned in JARM format.
   */
  callbacks: Pick<CallbackContext, "decryptJwe" | "verifyJwt">;
}

/**
 * Parsed and validated authorization response.
 */
export type ParseAuthorizationResponseResult = {
  authorizationResponsePayload: Openid4vpAuthorizationResponse;
  expectedNonce: string;
  jarm?: {
    jarmHeader: JarmHeader;
  } & VerifyJarmAuthorizationResponseResult;
} & ValidateOpenid4vpAuthorizationResponseResult;

/**
 * Parses an OpenID4VP authorization response and validates it against the request.
 *
 * If the response includes a `response` parameter, the JARM flow is used.
 * Otherwise, the plain authorization response payload is parsed and validated.
 *
 * @param options {@link ParseAuthorizationResponseOptions}
 * @returns A parsed and validated authorization response.
 */
export async function parseAuthorizationResponse(
  options: ParseAuthorizationResponseOptions,
): Promise<ParseAuthorizationResponseResult> {
  const { authorizationRequestPayload, authorizationResponse, callbacks } =
    options;

  if (authorizationResponse.response) {
    if (typeof authorizationResponse.response !== "string") {
      throw new Oid4vpError(
        "Invalid jarm authorization response: 'response' parameter must be a jwt string.",
      );
    }

    return parseJarmAuthorizationResponse({
      authorizationRequestPayload,
      callbacks,
      jarmResponseJwt: authorizationResponse.response,
    });
  }

  const authorizationResponsePayload = parseWithErrorHandling(
    zOpenid4vpAuthorizationResponse,
    authorizationResponse,
    "Failed to parse openid4vp authorization response.",
  );

  const validatedOpenId4vpResponse =
    validateOpenid4vpAuthorizationResponsePayload({
      authorizationRequestPayload: authorizationRequestPayload,
      authorizationResponsePayload: authorizationResponsePayload,
    });

  return {
    ...validatedOpenId4vpResponse,
    authorizationResponsePayload,
    expectedNonce: authorizationRequestPayload.nonce,
  };
}
