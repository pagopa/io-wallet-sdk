import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher } from "@openid4vc/utils";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { FetchAuthrorizationResponseError } from "../errors";
import { zOid4vpAuthorizationResponseResult } from "./z-authorization-response";

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
 * Sends a pushed authorization request to the authorization server and returns the response
 *
 * This function implements the IT Wallet Pushed Authorization Requests (PAR) specification,
 * sending the signed authorization request to the server and handling the response.
 *
 * @param options - Configuration options for the pushed authorization request
 * @returns Promise that resolves to the parsed pushed authorization response containing request_uri and expires_in
 * @throws {UnexpectedStatusCodeError} When the server returns a non-201 status code
 * @throws {ValidationError} When the response cannot be parsed or is invalid
 */
export async function fetchAuthorizationResponse(
  options: FetchAuthorizationResponseOptions,
): Promise<Response> {
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
      201,
      UnexpectedStatusCodeError,
    )(authorizationResponseResult);

    const authorizationResponseResultJson =
      await authorizationResponseResult.json();

    const parsedAuthorizationResponseResult =
      zOid4vpAuthorizationResponseResult.safeParse(
        authorizationResponseResultJson,
      );
    if (!parsedAuthorizationResponseResult.success) {
      throw new ValidationError(
        `Failed to parse pushed authorization response`,
        parsedAuthorizationResponseResult.error,
      );
    }

    //Response could be anything, so it's returned as is for further processing
    return fetch(parsedAuthorizationResponseResult.data.redirect_uri);
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new FetchAuthrorizationResponseError(
      `Unexpected error during pushed authorization request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
