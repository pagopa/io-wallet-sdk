import {
  RequestLike,
  formatZodError,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { Oauth2Error } from "../errors";
import { CallbackContext, decodeJwt } from "../index";
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
    authorizationRequest,
    request: options.request,
  });

  return {
    authorizationRequest,
    authorizationRequestJwt,
    clientAttestation,
    dpop,
  };
}
