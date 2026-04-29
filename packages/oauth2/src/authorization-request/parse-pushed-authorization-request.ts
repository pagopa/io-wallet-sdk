import { CallbackContext } from "@openid4vc/oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
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
} from "../jar/parse-jar-request";
import { zJarAuthorizationRequest } from "../jar/z-jar";
import {
  ParseAuthorizationRequestResult,
  parseAuthorizationRequest,
} from "./parse-authorization-request";
import {
  AuthorizationRequestV1_0,
  AuthorizationRequestV1_3,
  zAuthorizationRequestV1_0,
  zAuthorizationRequestV1_3,
} from "./z-authorization-request";

type AuthorizationRequest = AuthorizationRequestV1_0 | AuthorizationRequestV1_3;

export interface ParsePushedAuthorizationRequestOptions {
  authorizationRequest: unknown;
  callbacks: Pick<CallbackContext, "fetch">;
  config: IoWalletSdkConfig;
  request: RequestLike;
}

export interface ParsePushedAuthorizationRequestResult extends ParseAuthorizationRequestResult {
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
  const authorizationRequestSchema = getAuthorizationRequestSchema(
    options.config,
  );

  const parsed = parseWithErrorHandling(
    z.union([authorizationRequestSchema, zJarAuthorizationRequest]),
    options.authorizationRequest,
    "Invalid authorization request. Could not parse authorization request or jar.",
  );

  let parsedAuthorizationRequest: z.ZodSafeParseResult<AuthorizationRequest>;

  let authorizationRequestJwt: string | undefined;
  if (isJarAuthorizationRequest(parsed)) {
    const parsedJar = await parseJarRequest({
      callbacks: options.callbacks,
      jarRequestParams: parsed,
    });

    const jwt = decodeJwt({
      errorMessagePrefix: "Error decoding pushed authorization request JWT:",
      jwt: parsedJar.authorizationRequestJwt,
    });

    parsedAuthorizationRequest = authorizationRequestSchema.safeParse(
      jwt.payload,
    );
    if (!parsedAuthorizationRequest.success) {
      throw new Oauth2Error(
        `Invalid authorization request. Could not parse jar request payload.\n${formatZodError(parsedAuthorizationRequest.error)}`,
      );
    }

    authorizationRequestJwt = parsedJar.authorizationRequestJwt;
  } else {
    parsedAuthorizationRequest = authorizationRequestSchema.safeParse(
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

function getAuthorizationRequestSchema(config: IoWalletSdkConfig) {
  if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
    return zAuthorizationRequestV1_0;
  }

  if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
    return zAuthorizationRequestV1_3;
  }

  throw new ItWalletSpecsVersionError(
    "parsePushedAuthorizationRequest",
    config.itWalletSpecsVersion,
    [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
  );
}
