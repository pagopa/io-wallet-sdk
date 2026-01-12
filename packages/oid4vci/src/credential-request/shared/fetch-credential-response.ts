import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher, parseWithErrorHandling } from "@openid4vc/utils";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";
import { ZodSchema } from "zod";

import { FetchCredentialResponseError } from "../../errors";

/**
 * Shared options for fetching credential responses across all versions
 */
export interface SharedFetchCredentialResponseOptions<
  TCredentialRequest,
  TCredentialResponse,
> {
  accessToken: string;
  callbacks: Pick<CallbackContext, "fetch">;
  credentialEndpoint: string;
  credentialRequest: TCredentialRequest;
  dPoP: string;
  responseSchema: ZodSchema<TCredentialResponse>;
}

/**
 * Shared implementation for fetching credential responses.
 *
 * This generic function handles the HTTP POST request and response validation
 * for all IT-Wallet specification versions.
 *
 * @param options - Configuration including endpoint, request, auth tokens, and schema
 * @returns Parsed credential response according to the provided schema
 * @throws {FetchCredentialResponseError} When network or unexpected errors occur
 * @throws {UnexpectedStatusCodeError} When issuer returns non-200 status
 * @throws {ValidationError} When response doesn't match expected schema
 */
export async function sharedFetchCredentialResponse<
  TCredentialRequest,
  TCredentialResponse,
>(
  options: SharedFetchCredentialResponseOptions<
    TCredentialRequest,
    TCredentialResponse
  >,
): Promise<TCredentialResponse> {
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
      options.responseSchema,
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
