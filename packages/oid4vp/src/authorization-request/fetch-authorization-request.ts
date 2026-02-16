import { type CallbackContext, Oauth2JwtParseError } from "@openid4vc/oauth2";
import { ValidationError, createFetcher } from "@openid4vc/utils";
import {
  UnexpectedStatusCodeError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { Oid4vpError } from "../errors";
import { validateAuthorizationRequestParams } from "./validate-authorization-request";
import { zAuthorizationRequestUrlParams } from "./z-authorization-request-url";

export interface FetchAuthorizationRequestOptions {
  /**
   * The authorization URL from the QR code
   * Should contain `client_id` and either `request` or `request_uri` query parameters
   */
  authorizeRequestUrl: string;

  /**
   * Callback functions for making HTTP requests
   * Allows for custom fetch implementation
   */
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * Optional wallet metadata to send when request_uri_method=post.
   * If not provided and POST is required, sends an empty body (basic implementation).
   *
   * Specification: IT-Wallet v1.3.3 recommends (SHOULD) sending wallet capabilities
   * in application/x-www-form-urlencoded format when using POST.
   */
  walletMetadata?: {
    authorization_endpoint?: string;
    client_id_prefixes_supported?: string[];
    request_object_signing_alg_values_supported?: string[];
    response_modes_supported?: string[];
    response_types_supported?: string[];
    vp_formats_supported?: Record<string, unknown>;
  };

  /**
   * Optional wallet nonce for replay attack prevention (RECOMMENDED per spec)
   */
  walletNonce?: string;
}

export interface ParsedQrCode {
  /**
   * The `client_id` from the authorization URL
   */
  clientId: string;
  /**
   * The `request_uri` from the authorization URL
   */
  requestUri?: string;
  /**
   * The `request_uri_method` from the authorization URL (get or post)
   */
  requestUriMethod?: "get" | "post";
}

export interface FetchAuthorizationRequestResult {
  /**
   * The parsed QR code data
   * Includes `clientId`, `requestUri` and `requestUriMethod`
   */
  parsedQrCode: ParsedQrCode;

  /**
   * The original Request Object JWT, either fetched from `request_uri` or extracted from `request` parameter.
   */
  requestObjectJwt: string;

  /**
   * Transmission mode indicator
   * - "value": Request Object JWT passed inline via `request` parameter
   * - "reference": Request Object JWT fetched from `request_uri`
   */
  sendBy: "reference" | "value";
}

/**
 * Helper function to fetch Request Object JWT from request_uri.
 * Supports GET and POST methods, with optional wallet metadata for POST.
 *
 * @param requestUri - URI to fetch Request Object from
 * @param options - Fetch options including method and wallet metadata
 * @returns The Request Object JWT as a string
 * @throws {UnexpectedStatusCodeError} If the server returns a non-200 status code
 * @throws {Error} If the underlying fetch/createFetcher call fails (for example, due to network errors)
 */
export async function fetchRequestObjectJwt(
  requestUri: string,
  options: {
    fetch: CallbackContext["fetch"];
    method: "get" | "post";
    walletMetadata?: FetchAuthorizationRequestOptions["walletMetadata"];
    walletNonce?: string;
  },
): Promise<string> {
  const fetch = createFetcher(options.fetch);

  // Prepare request configuration
  const requestInit: RequestInit = {
    method: options.method.toUpperCase(),
  };

  // Add body for POST requests per IT-Wallet spec (SHOULD include metadata)
  if (options.method === "post") {
    const formData = new URLSearchParams();

    // Add wallet_metadata if provided (spec: OPTIONAL)
    if (options.walletMetadata) {
      formData.append(
        "wallet_metadata",
        JSON.stringify(options.walletMetadata),
      );
    }

    // Add wallet_nonce if provided (spec: RECOMMENDED)
    if (options.walletNonce) {
      formData.append("wallet_nonce", options.walletNonce);
    }

    requestInit.headers = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    requestInit.body = formData.toString();
  }

  const response = await fetch(requestUri, requestInit);

  await hasStatusOrThrow(200, UnexpectedStatusCodeError)(response);

  return await response.text();
}

/**
 * Fetches an OpenID4VP authorization request JWT from a QR code URL.
 *
 * Supports two transmission modes:
 * - **By Value**: Request Object JWT passed inline via `request` parameter
 * - **By Reference**: Request Object JWT fetched from `request_uri`
 *
 * The function:
 * 1. Parses the authorization URL to extract parameters
 * 2. Validates that exactly one of `request` or `request_uri` is present
 * 3. Either uses inline JWT or fetches from URI (GET/POST based on request_uri_method)
 * 4. Returns the Request Object JWT along with transmission mode metadata
 *
 * Note: This function does NOT parse or verify the JWT. Use {@link parseAuthorizeRequest}
 * separately to decode and optionally verify the signature.
 *
 * @param options {@link FetchAuthorizationRequestOptions}
 * @returns Promise that resolves to {@link FetchAuthorizationRequestResult}
 * @throws {Oid4vpError} When required query parameters are missing, the URL is invalid, or an unexpected error occurs during fetch or parsing
 * @throws {UnexpectedStatusCodeError} When the server returns a non-200 status code during fetch
 * @throws {ValidationError} When URL parameters fail schema validation
 *
 * @example By Value mode
 * ```typescript
 * const url = "https://wallet.example.org/authorize?" +
 *   "client_id=openid_federation%23https%3A%2F%2Frp.example.org" +
 *   "&request=eyJhbGciOiJFUzI1NiIs...";
 *
 * const result = await fetchAuthorizationRequest({
 *   authorizeRequestUrl: url,
 *   callbacks: { fetch },
 * });
 * // result.sendBy === "value"
 * // result.requestObjectJwt === "eyJhbGciOiJFUzI1NiIs..."
 * ```
 *
 * @example By Reference mode with POST
 * ```typescript
 * const url = "https://wallet.example.org/authorize?" +
 *   "client_id=openid_federation%23https%3A%2F%2Frp.example.org" +
 *   "&request_uri=https%3A%2F%2Frp.example.org%2Frequest" +
 *   "&request_uri_method=post";
 *
 * const result = await fetchAuthorizationRequest({
 *   authorizeRequestUrl: url,
 *   callbacks: { fetch },
 *   walletMetadata: {
 *     authorization_endpoint: "https://wallet.example.org/authorize",
 *     response_types_supported: ["vp_token"],
 *   },
 *   walletNonce: "random-nonce",
 * });
 * // result.sendBy === "reference"
 * // result.requestObjectJwt === fetched JWT from request_uri
 * ```
 */
export async function fetchAuthorizationRequest(
  options: FetchAuthorizationRequestOptions,
): Promise<FetchAuthorizationRequestResult> {
  try {
    const url = new URL(options.authorizeRequestUrl);

    // Extract and validate URL parameters using Zod schema
    const rawParams = {
      client_id: url.searchParams.get("client_id") ?? undefined,
      request: url.searchParams.get("request") ?? undefined,
      request_uri: url.searchParams.get("request_uri") ?? undefined,
      request_uri_method:
        url.searchParams.get("request_uri_method") ?? undefined,
      state: url.searchParams.get("state") ?? undefined,
    };

    // Parse and validate URL parameters with Zod schema
    const parsedParams = zAuthorizationRequestUrlParams.parse(rawParams);

    // Validate business logic (mutual exclusivity, etc.)
    const validatedParams = validateAuthorizationRequestParams(parsedParams);

    // Determine transmission mode
    const sendBy = validatedParams.request ? "value" : "reference";

    // Get JWT: either inline or fetch from URI
    let requestObjectJwt: string;
    if (validatedParams.request) {
      requestObjectJwt = validatedParams.request;
    } else {
      // Type system guarantees request_uri is defined here due to validation
      requestObjectJwt = await fetchRequestObjectJwt(
        validatedParams.request_uri as string,
        {
          fetch: options.callbacks.fetch,
          method: validatedParams.request_uri_method ?? "get",
          walletMetadata: options.walletMetadata,
          walletNonce: options.walletNonce,
        },
      );
    }

    return {
      parsedQrCode: {
        clientId: validatedParams.client_id,
        requestUri: validatedParams.request_uri,
        requestUriMethod:
          sendBy === "reference"
            ? (validatedParams.request_uri_method ?? "get")
            : undefined,
      },
      requestObjectJwt,
      sendBy,
    };
  } catch (error) {
    if (
      error instanceof ValidationError ||
      error instanceof Oauth2JwtParseError ||
      error instanceof Oid4vpError ||
      error instanceof UnexpectedStatusCodeError
    ) {
      throw error;
    }

    throw new Oid4vpError(
      `Unexpected error during fetch authorization request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
