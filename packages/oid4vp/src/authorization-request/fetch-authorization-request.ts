import type { CallbackContext, RequestDpopOptions } from "@openid4vc/oauth2";

import { ValidationError, createFetcher } from "@openid4vc/utils";

import type { AuthorizationRequestObject } from "./z-request-object";

import { Oid4vpError } from "../errors";
import { parseAuthorizeRequest } from "./parse-authorization-request";

export interface FetchAuthorizationRequestOptions {
  /**
   * The authorization URL from the QR code
   * Should contain `client_id` and `request_uri` query parameters
   */
  authorizeRequestUrl: string;

  /**
   * Callback functions for making HTTP requests and JWT verification
   * Allows for custom fetch and verifyJwt implementations
   */
  callbacks: Pick<CallbackContext, "fetch" | "verifyJwt">;

  /**
   * DPoP options for JWT verification
   */
  dpop: RequestDpopOptions;
}

export interface FetchAuthorizationRequestResult {
  /**
   * The base URI of the authorization request
   */
  baseUri: string;
  /**
   * The path of the authorization request
   */
  path: string;
  /**
   * The parsed authorization request object
   */
  requestObject: AuthorizationRequestObject;
  /**
   * The query parameters of the authorization request
   */
  searchParams: URLSearchParams;
}

/**
 * Fetches and parses an OpenID4VP authorization request from a QR code URL.
 *
 * This function:
 * 1. Verifies that `client_id` and `request_uri` query parameters are present
 * 2. Fetches the request object JWT from request_uri using GET or POST based on `request_uri_method`
 * 3. Parses and verifies the request object JWT
 * 4. Returns the parsed request object along with URL components
 *
 * @param options {@link FetchAuthorizationRequestOptions}
 * @returns Promise that resolves to {@link FetchAuthorizationRequestResult}
 * @throws {Oid4vpError} When required query parameters are missing or URL is invalid
 * @throws {ValidationError} When the request object cannot be parsed or is invalid
 * @throws {ParseAuthorizeRequestError} When JWT verification fails
 */
export async function fetchAuthorizationRequest(
  options: FetchAuthorizationRequestOptions,
): Promise<FetchAuthorizationRequestResult> {
  try {
    const url = new URL(options.authorizeRequestUrl);

    // Verify required query parameters
    const requestUri = url.searchParams.get("request_uri");
    const clientId = url.searchParams.get("client_id");

    if (!clientId) {
      throw new Oid4vpError("Missing required query parameter: client_id");
    }

    if (!requestUri) {
      throw new Oid4vpError("Missing required query parameter: request_uri");
    }

    // Determine request method (default to GET if not specified)
    const requestUriMethod = url.searchParams.get("request_uri_method");
    const method = requestUriMethod?.toUpperCase() === "POST" ? "POST" : "GET";

    // Fetch the request object JWT
    const fetch = createFetcher(options.callbacks.fetch);
    const response = await fetch(url, {
      method,
    });

    if (!response.ok) {
      throw new Oid4vpError(
        `Failed to fetch request object: ${response.status} ${response.statusText}`,
        response.status,
      );
    }

    const requestObjectJwt = await response.text();

    // Parse and verify the request object
    const requestObject = await parseAuthorizeRequest({
      callbacks: options.callbacks,
      dpop: options.dpop,
      requestObjectJwt,
    });

    return {
      baseUri: url.origin,
      path: url.pathname,
      requestObject,
      searchParams: url.searchParams,
    };
  } catch (error) {
    if (error instanceof Oid4vpError || error instanceof ValidationError) {
      throw error;
    }
    throw new Oid4vpError(
      `Unexpected error fetching authorization request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
