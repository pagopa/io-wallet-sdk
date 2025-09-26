import { CallbackContext } from "@openid4vc/oauth2";

import { CONTENT_TYPES, HEADERS } from "../constants";
import { Oauth2ParseError } from "../error/Oauth2ParseError";
import { NonceResponse, zNonceResponse } from "./z-nonce-response";

/**
 * Custom error thrown when nonce request operations fail
 */
export class NonceRequestError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number
  ) {
    super(message);
    this.name = "NonceRequestError";
  }
}

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
export async function fetchPushedAuthorizationRequest(
  options: GetNonceOptions
): Promise<NonceResponse> {
  try {
    const nonceResponse = await options.callbacks.fetch(options.nonceUrl, {
      method: "POST",
    });

    if (nonceResponse.status !== 201) {
      const errorText = await nonceResponse.text().catch(() => "Unknown error");
      throw new NonceRequestError(
        `Nonce request failed with status ${nonceResponse.status}. Expected 201 Created. Response: ${errorText}`,
        nonceResponse.status
      );
    }

    const nonceResponseJson = await nonceResponse.json();

    const parsedNonceResponse = zNonceResponse.safeParse(nonceResponseJson);
    if (!parsedNonceResponse.success) {
      throw new Oauth2ParseError(
        `Failed to parse nonce response: ${parsedNonceResponse.error.message}`,
        parsedNonceResponse.error
      );
    }

    return parsedNonceResponse.data;
  } catch (error) {
    if (
      error instanceof NonceRequestError ||
      error instanceof Oauth2ParseError
    ) {
      throw error;
    }
    throw new NonceRequestError(
      `Unexpected error during nonce request: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
