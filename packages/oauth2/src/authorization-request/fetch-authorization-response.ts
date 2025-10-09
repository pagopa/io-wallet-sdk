import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher } from "@openid4vc/utils";
import {
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { CONTENT_TYPES, HEADERS } from "../constants";
import { PushedAuthorizationRequestError } from "../error";
import {
  PushedAuthorizationRequestSigned,
  PushedAuthorizationResponse,
  zPushedAuthorizationResponse,
} from "./z-authorization-request";

/**
 * Configuration options for fetching pushed authorization response
 */
export interface fetchPushedAuthorizationResponseOptions {
  /**
   * Callback functions for making HTTP requests
   * Allows for custom fetch implementations
   */
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * The client attestation Demonstration of Proof-of-Possession (DPoP) token
   * Used for OAuth-Client-Attestation-PoP header to prove possession of the client key
   */
  clientAttestationDPoP: string;

  /**
   * The endpoint URL where the pushed authorization request will be sent
   * This should be the authorization server's PAR endpoint
   */
  pushedAuthorizationRequestEndpoint: string;

  /**
   * The signed pushed authorization request object containing client_id and request JWT
   * This object has been previously signed and is ready for transmission
   */
  pushedAuthorizationRequestSigned: PushedAuthorizationRequestSigned;

  /**
   * The wallet attestation JWT that proves the client's identity and capabilities
   * Used for OAuth-Client-Attestation header
   */
  walletAttestation: string;
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
export async function fetchPushedAuthorizationResponse(
  options: fetchPushedAuthorizationResponseOptions,
): Promise<PushedAuthorizationResponse> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);
    const parResponse = await fetch(
      options.pushedAuthorizationRequestEndpoint,
      {
        body: new URLSearchParams({
          clientId: options.pushedAuthorizationRequestSigned.client_id,
          request: options.pushedAuthorizationRequestSigned.request,
        }),
        headers: {
          [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.FORM_URLENCODED,
          [HEADERS.OAUTH_CLIENT_ATTESTATION]: options.walletAttestation,
          [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]: options.clientAttestationDPoP,
        },
        method: "POST",
      },
    );

    await hasStatusOrThrow(201, UnexpectedStatusCodeError)(parResponse);

    const parResponseJson = await parResponse.json();

    const parsedParResponse =
      zPushedAuthorizationResponse.safeParse(parResponseJson);
    if (!parsedParResponse.success) {
      throw new ValidationError(
        `Failed to parse pushed authorization response`,
        parsedParResponse.error,
      );
    }

    return parsedParResponse.data;
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new PushedAuthorizationRequestError(
      `Unexpected error during pushed authorization request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
