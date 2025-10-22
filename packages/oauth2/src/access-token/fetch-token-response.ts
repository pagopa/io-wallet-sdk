import { CallbackContext } from "@openid4vc/oauth2";
import { ValidationError, createFetcher } from "@openid4vc/utils";
import {
  UnexpectedStatusCodeError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { CONTENT_TYPES, HEADERS } from "../constants";
import { FetchTokenResponseError } from "../errors";
import {
  AccessTokenRequest,
  AccessTokenResponse,
  zAccessTokenResponse,
} from "./z-token";

export interface FetchTokenResponseOptions {
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
   * The client attestation Demonstration of Proof-of-Possession (DPoP) token
   * Used for OAuth-Client-Attestation-PoP header to prove possession of the client key
   */
  clientAttestationDPoP: string;

  /**
   * The wallet attestation JWT that proves the client's identity and capabilities
   * Used for OAuth-Client-Attestation header
   */
  walletAttestation: string;
}

/**
 * Sends an access token request to the authorization server and returns the response
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
    const tokenResponse = await fetch(options.accessTokenEndpoint, {
      body: toURLSearchParams(options.accessTokenRequest),
      headers: {
        [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.FORM_URLENCODED,
        [HEADERS.OAUTH_CLIENT_ATTESTATION]: options.walletAttestation,
        [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]: options.clientAttestationDPoP,
      },
      method: "POST",
    });

    await hasStatusOrThrow(200, UnexpectedStatusCodeError)(tokenResponse);

    const tokenResponseJson = await tokenResponse.json();

    const parsedTokenResponse =
      zAccessTokenResponse.safeParse(tokenResponseJson);
    if (!parsedTokenResponse.success) {
      throw new ValidationError(
        `Failed to parse token response`,
        parsedTokenResponse.error,
      );
    }

    return parsedTokenResponse.data;
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new FetchTokenResponseError(
      `Unexpected error during token respone: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

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
