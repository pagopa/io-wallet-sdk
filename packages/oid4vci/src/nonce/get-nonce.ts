import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher } from "@openid4vc/utils";
import {
  UnexpectedStatusCodeError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";
import * as z from "zod";

import { NonceParseError, NonceRequestError } from "../errors";
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
 * @throws {PushedAuthorizationRequestError} When the server returns a non-201 status code
 * @throws {PushedAuthorizationResponseParseError} When the response cannot be parsed or is invalid
 */
export async function getNonce(
  options: GetNonceOptions,
): Promise<NonceResponse> {
  const fetch = createFetcher(options.callbacks.fetch);
  return await fetch(options.nonceUrl, {
    method: "POST",
  })
    .then(hasStatusOrThrow(200, UnexpectedStatusCodeError))
    .then((res) => res.json())
    .then(zNonceResponse.parse)
    .catch((error: unknown) => {
      if (error instanceof z.ZodError) {
        throw new NonceParseError(
          `Failed to parse nonce response: ${error.message}`,
          error,
        );
      }
      throw new NonceRequestError(
        `Unexpected error during nonce request: ${error instanceof Error ? error.message : String(error)}`,
      );
    });
}
