import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher, parseWithErrorHandling } from "@openid4vc/utils";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import type { CredentialRequestV1_0 } from "./v1.0";
import type { CredentialRequestV1_3 } from "./v1.3";

import { FetchCredentialResponseError } from "../errors";
import { CredentialResponse, zCredentialResponse } from "./z-credential";

/**
 * Options for fetching credential response
 * Accepts credential requests from any supported version
 */
export interface FetchCredentialResponseOptions {
  accessToken: string;
  callbacks: Pick<CallbackContext, "fetch">;
  credentialEndpoint: string;
  /**
   * Credential request object (supports both v1.0 and v1.3 formats)
   */
  credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
  dPoP: string;
}

/**
 * Fetch a credential response from the credential endpoint
 *
 * Supports both v1.0 and v1.3 credential request formats.
 * The response format is version-agnostic.
 *
 * @param options - Configuration for credential fetch
 * @returns Parsed credential response
 * @throws {UnexpectedStatusCodeError} If HTTP status is not 200
 * @throws {ValidationError} If response validation fails
 * @throws {FetchCredentialResponseError} For unexpected errors
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
      `Unexpected error during credential response: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}
