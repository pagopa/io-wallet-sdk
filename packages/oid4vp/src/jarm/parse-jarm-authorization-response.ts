import {
  type CallbackContext,
  decodeJwtHeader,
  zCompactJwe,
  zCompactJwt,
} from "@pagopa/io-wallet-oauth2";
import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import z from "zod";

import { Openid4vpAuthorizationRequestPayload } from "../authorization-request";
import {
  ParseAuthorizationResponseResult,
  validateOpenid4vpAuthorizationResponsePayload,
  zOpenid4vpAuthorizationResponse,
} from "../authorization-response";
import { verifyJarmAuthorizationResponse } from "./verify-jarm-authorization-response";
import { zJarmHeader } from "./z-jarm";

export interface ParseJarmAuthorizationResponseOptions {
  /**
   * Parsed authorization request payload used to validate JARM claims.
   */
  authorizationRequestPayload: Openid4vpAuthorizationRequestPayload;
  /**
   * Callbacks used to decrypt and verify JARM JWT/JWE responses.
   */
  callbacks: Pick<CallbackContext, "decryptJwe" | "verifyJwt">;
  /**
   * Compact JARM authorization response (`response` parameter value).
   */
  jarmResponseJwt: string;
}

/**
 * Parses and validates a JARM authorization response for OpenID4VP.
 *
 * This function validates compact format, decrypts and/or verifies the JARM token,
 * parses the resulting OpenID4VP authorization response, and validates it against
 * the originating authorization request.
 *
 * @param options {@link ParseJarmAuthorizationResponseOptions}
 * @returns Parsed authorization response enriched with JARM metadata.
 */
export async function parseJarmAuthorizationResponse(
  options: ParseJarmAuthorizationResponseOptions,
): Promise<ParseAuthorizationResponseResult> {
  const { authorizationRequestPayload, callbacks, jarmResponseJwt } = options;

  const jarmAuthorizationResponseJwt = parseWithErrorHandling(
    z.union([zCompactJwt, zCompactJwe]),
    jarmResponseJwt,
    "Invalid jarm authorization response jwt.",
  );

  const verifiedJarmResponse = await verifyJarmAuthorizationResponse({
    authorizationRequestPayload,
    callbacks,
    jarmAuthorizationResponseJwt,
  });

  const { header: jarmHeader } = decodeJwtHeader({
    headerSchema: zJarmHeader,
    jwt: jarmAuthorizationResponseJwt,
  });

  const authorizationResponsePayload = parseWithErrorHandling(
    zOpenid4vpAuthorizationResponse,
    verifiedJarmResponse.jarmAuthorizationResponse,
    "Failed to parse openid4vp authorization response.",
  );

  const validateOpenId4vpResponse =
    validateOpenid4vpAuthorizationResponsePayload({
      authorizationRequestPayload: authorizationRequestPayload,
      authorizationResponsePayload: authorizationResponsePayload,
    });

  return {
    ...validateOpenId4vpResponse,
    authorizationResponsePayload,
    expectedNonce: authorizationRequestPayload.nonce,
    jarm: { ...verifiedJarmResponse, jarmHeader },
  };
}
