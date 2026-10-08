import {
  CONTENT_TYPES,
  type CallbackContext,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  createFetcher,
  hasStatusOrThrow,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import {
  type ClientAttestationHeadersOptions,
  getClientAttestationHeaders,
} from "../client-attestation/client-attestation-headers";
import { ClientAttestationError, FetchTokenResponseError } from "../errors";
import {
  type DpopProof,
  fetchWithDpopNonceRetry,
} from "../token-dpop/dpop-utils";
import {
  AccessTokenRequest,
  AccessTokenResponse,
  zAccessTokenResponse,
} from "./z-token";

export interface FetchTokenResponseOptions extends ClientAttestationHeadersOptions {
  /**
   * The endpoint URL where the access token request will be sent
   * This should be the authorization server's token endpoint
   */
  accessTokenEndpoint: string;

  /**
   * The access token request payload
   */
  accessTokenRequest: AccessTokenRequest;

  /**
   * Callbacks to use for requesting access token
   */
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * DPoP proof for the token request. When a factory is provided, the request is
   * retried once with the nonce required by the server (RFC 9449, Section 8).
   */
  dPoP: DpopProof;
}

/**
 * Sends an access token request to the authorization server and returns the response
 *
 * The client authenticates with its Wallet Attestation when `walletAttestation` and
 * `clientAttestationDPoP` are provided, otherwise as a public client identified by the
 * `client_id` of the request.
 *
 * @param options - Configuration options for the access token request
 * @returns Promise that resolves to the parsed access token response
 * @throws {UnexpectedStatusCodeError} When the server returns a non-200 status code
 * @throws {ValidationError} When the response cannot be parsed as a valid access token response
 * @throws {FetchTokenResponseError} When an unexpected error occurs during the request
 */

export async function fetchTokenResponse(
  options: FetchTokenResponseOptions,
): Promise<AccessTokenResponse> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);
    const tokenResponse = await fetchWithDpopNonceRetry({
      dPoP: options.dPoP,
      sendRequest: async (dPoP) =>
        fetch(options.accessTokenEndpoint, {
          body: toURLSearchParams(options.accessTokenRequest),
          headers: {
            [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.FORM_URLENCODED,
            [HEADERS.DPOP]: dPoP,
            ...(await getClientAttestationHeaders(options)),
          },
          method: "POST",
        }),
    });

    await hasStatusOrThrow(200, UnexpectedStatusCodeError)(tokenResponse);

    return parseWithErrorHandling(
      zAccessTokenResponse,
      await tokenResponse.json(),
      "Failed to parse token response",
    );
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError ||
      error instanceof ClientAttestationError
    ) {
      throw error;
    }
    throw new FetchTokenResponseError(
      `Unexpected error during token respone: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Converts an access token request object into URL-encoded form parameters.
 *
 * Object values are JSON-stringified so structured extension parameters such as
 * `authorization_details` can be sent in `application/x-www-form-urlencoded` requests.
 *
 * @param data - Access token request payload.
 * @returns URLSearchParams containing all defined request fields.
 */
export function toURLSearchParams(data: AccessTokenRequest): URLSearchParams {
  const params = new URLSearchParams();

  Object.entries(data).forEach(([key, value]) => {
    if (value === undefined) return;

    params.append(
      key,
      typeof value === "object" ? JSON.stringify(value) : String(value),
    );
  });

  return params;
}
