import { CallbackContext } from "@openid4vc/oauth2";
import { ValidationError, createFetcher } from "@openid4vc/utils";
import {
  UnexpectedStatusCodeError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { NonceRequestError } from "../errors";
import { NonceResponse, zNonceResponse } from "./z-nonce-response";

/**
 * Configuration options for fetching pushed authorization requests
 */
export interface GetNonceOptions {
  /**
   * Callback functions for making HTTP requests
   * Allows for custom fetch implementations
   */
  callbacks: Pick<CallbackContext, "fetch">;

  nonceUrl: string;
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
 * @throws {NonceRequestError} When an unexpected error occurs during the request
 */
export async function getNonce(
  options: GetNonceOptions,
): Promise<NonceResponse> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);
    const nonceResponse = await fetch(options.nonceUrl, {
      method: "POST",
    });

    await hasStatusOrThrow(200, UnexpectedStatusCodeError)(nonceResponse);

    const nonceResponseJson = await nonceResponse.json();

    const parsedNonceResponse = zNonceResponse.safeParse(nonceResponseJson);
    if (!parsedNonceResponse.success) {
      throw new ValidationError(
        `Failed to parse nonce response`,
        parsedNonceResponse.error,
      );
    }

    return parsedNonceResponse.data;
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new NonceRequestError(
      `Unexpected error during nonce request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
