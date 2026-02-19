import { CallbackContext } from "@openid4vc/oauth2";
import {
  RequestLike,
  formatZodError,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { decodeJwt } from "../common/jwt/decode-jwt";
import { Oauth2Error } from "../errors";
import {
  isJarAuthorizationRequest,
  parseJarRequest,
  zJarAuthorizationRequest,
} from "../jar";
import {
  ParseAuthorizationRequestResult,
  parseAuthorizationRequest,
} from "./parse-authorization-request";
import {
  AuthorizationRequest,
  zAuthorizationRequest,
} from "./z-authorization-request";

export interface ParsePushedAuthorizationRequestOptions {
  authorizationRequest: unknown;
  callbacks: Pick<CallbackContext, "fetch">;
  request: RequestLike;
}

export interface ParsePushedAuthorizationRequestResult
  extends ParseAuthorizationRequestResult {
  authorizationRequest: AuthorizationRequest;

  /**
   * The JWT-secured request object, if the request was pushed as a JAR.
   * May be undefined if the request object is not a JAR.
   */
  authorizationRequestJwt?: string;
}

/**
 * Parses and validates a pushed authorization request (PAR).
 *
 * Handles both standard authorization requests and JWT-secured Authorization Requests (JAR).
 * When a JAR is provided, it validates the JWT structure, decodes it, and extracts the
 * authorization request from the payload. Also extracts client attestation and DPoP proofs
 * from the HTTP request headers.
 *
 * @param options - Configuration for parsing the pushed authorization request
 * @param options.authorizationRequest - The authorization request data to parse (can be standard or JAR format)
 * @param options.callbacks - Callbacks for external operations (requires `fetch` for JAR validation)
 * @param options.request - The HTTP request object containing headers for client attestation and DPoP
 * @returns A promise resolving to the parsed authorization request with extracted metadata
 * @throws {Oauth2Error} When the authorization request is invalid or cannot be parsed
 */
export async function parsePushedAuthorizationRequest(
  options: ParsePushedAuthorizationRequestOptions,
): Promise<ParsePushedAuthorizationRequestResult> {
  const parsed = parseWithErrorHandling(
    z.union([zAuthorizationRequest, zJarAuthorizationRequest]),
    options.authorizationRequest,
    "Invalid authorization request. Could not parse authorization request or jar.",
  );

  let parsedAuthorizationRequest: ReturnType<
    typeof zAuthorizationRequest.safeParse
  >;

  let authorizationRequestJwt: string | undefined;
  if (isJarAuthorizationRequest(parsed)) {
    const parsedJar = await parseJarRequest({
      callbacks: options.callbacks,
      jarRequestParams: parsed,
    });

    const jwt = decodeJwt({ jwt: parsedJar.authorizationRequestJwt });

    parsedAuthorizationRequest = zAuthorizationRequest.safeParse(jwt.payload);
    if (!parsedAuthorizationRequest.success) {
      throw new Oauth2Error(
        `Invalid authorization request. Could not parse jar request payload.\n${formatZodError(parsedAuthorizationRequest.error)}`,
      );
    }

    authorizationRequestJwt = parsedJar.authorizationRequestJwt;
  } else {
    parsedAuthorizationRequest = zAuthorizationRequest.safeParse(
      options.authorizationRequest,
    );
    if (!parsedAuthorizationRequest.success) {
      throw new Oauth2Error(
        `Error occurred during validation of pushed authorization request.\n${formatZodError(parsedAuthorizationRequest.error)}`,
      );
    }
  }

  const authorizationRequest = parsedAuthorizationRequest.data;
  const { clientAttestation, dpop } = parseAuthorizationRequest({
    request: options.request,
  });

  return {
    authorizationRequest,
    authorizationRequestJwt,
    clientAttestation,
    dpop,
  };
}
