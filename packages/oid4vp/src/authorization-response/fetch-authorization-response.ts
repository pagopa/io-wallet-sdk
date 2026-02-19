import { CallbackContext } from "@openid4vc/oauth2";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  createFetcher,
  hasStatusOrThrow,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { FetchAuthorizationResponseError } from "../errors";
import {
  Oid4vpAuthorizationResponseResult,
  zOid4vpAuthorizationResponseResult,
} from "./z-authorization-response";

/**
 * Configuration options for fetching OID4VP Presentation Result
 */
export interface FetchAuthorizationResponseOptions {
  /**
   * The signed and encrypted {@link Openid4vpAuthorizationResponse} in base64 format
   */
  authorizationResponseJarm: string;

  /**
   * Callback functions for making HTTP requests
   * Allows for custom fetch implementations
   */
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * The response_uri field contained in the {@link AuthorizationRequestObject}
   */
  presentationResponseUri: string;
}

/**
 * Sends the {@link Openid4vpAuthorizationResponse} to the response uri provided by the session's
 * {@link AuthorizationRequestObject} and returns the {@link Oid4vpAuthorizationResponseResult} object
 * containing the redirect_uri at which to continue the presentation
 *
 * @param options {@link FetchAuthorizationResponseOptions}
 * @returns Promise that resolves to the parsed {@link Oid4vpAuthorizationResponseResult}
 * @throws {UnexpectedStatusCodeError} When the server returns a non-200 status code
 * @throws {ValidationError} When the response cannot be parsed or is invalid
 */
export async function fetchAuthorizationResponse(
  options: FetchAuthorizationResponseOptions,
): Promise<Oid4vpAuthorizationResponseResult> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);
    const authorizationResponseResult = await fetch(
      options.presentationResponseUri,
      {
        body: new URLSearchParams({
          response: options.authorizationResponseJarm,
        }),
        headers: {
          [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.FORM_URLENCODED,
        },
        method: "POST",
      },
    );

    await hasStatusOrThrow(
      200,
      UnexpectedStatusCodeError,
    )(authorizationResponseResult);

    const authorizationResponseResultJson =
      await authorizationResponseResult.json();

    //Response could be anything, so it's returned as is for further processing
    return parseWithErrorHandling(
      zOid4vpAuthorizationResponseResult,
      authorizationResponseResultJson,
    );
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new FetchAuthorizationResponseError(
      `Unexpected error sending authorization response: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
