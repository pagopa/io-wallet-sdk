import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher, parseWithErrorHandling } from "@openid4vc/utils";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { FetchCredentialResponseError } from "../errors";
import {
  CredentialRequest,
  CredentialResponse,
  zCredentialResponse,
} from "./z-credential";

export interface FetchCredentialResponseOptions {
  /**
   * Access token to authorize the credential request for DPoP mechanism
   */
  accessToken: string;
  /**
   * Callbacks to use for requesting access token
   */
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * The credential endpoint URL
   */
  credentialEndpoint: string;

  /**
   * Credential request body
   */
  credentialRequest: CredentialRequest;

  /**
   * DPoP proof with addition of ath claim
   */
  dPoP: string;
}

/**
 * Fetches a credential response from the credential endpoint.
 *
 * @param options - Options for fetching the credential response
 * @returns The credential response
 * @throws FetchCredentialResponseError if an unexpected error occurs during the fetch
 * @throws UnexpectedStatusCodeError if the response status code is not 200
 * @throws ValidationError if the response cannot be parsed as a valid credential response
 */
export async function fetchCredentialResponse(
  options: FetchCredentialResponseOptions,
): Promise<CredentialResponse> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);
    const credentialResponse = await fetch(options.credentialEndpoint, {
      body: JSON.stringify(options.credentialRequest),
      headers: {
        [HEADERS.AUTHORIZATION]: `DPoP ${options.accessToken}`,
        [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.JSON,
        [HEADERS.DPOP]: options.dPoP,
      },
      method: "POST",
    });

    await hasStatusOrThrow(200, UnexpectedStatusCodeError)(credentialResponse);

    const credentialResponseJson = await credentialResponse.json();

    return parseWithErrorHandling(
      zCredentialResponse,
      credentialResponseJson,
      `Failed to parse credential response`,
    );
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new FetchCredentialResponseError(
      `Unexpected error during credential response: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
