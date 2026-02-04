import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher } from "@openid4vc/utils";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { PushedAuthorizationRequestError } from "../errors";
import {
  PushedAuthorizationRequest,
  PushedAuthorizationResponse,
  isPushedAuthorizationRequestSigned,
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
   * The pushed authorization request to send. Accepts both signed (JAR) and unsigned variants
   * as returned by `createPushedAuthorizationRequest`. The correct form body is derived
   * automatically: signed requests POST `{ client_id, request }`, unsigned requests POST
   * every field from `authorizationRequest` as flat form parameters.
   */
  pushedAuthorizationRequest: PushedAuthorizationRequest;

  /**
   * The endpoint URL where the pushed authorization request will be sent
   * This should be the authorization server's PAR endpoint
   */
  pushedAuthorizationRequestEndpoint: string;

  /**
   * The wallet attestation JWT that proves the client's identity and capabilities
   * Used for OAuth-Client-Attestation header
   */
  walletAttestation: string;
}

/**
 * Sends a pushed authorization request to the authorization server and returns the response.
 *
 * Supports both signed (JAR) and unsigned PAR variants as produced by
 * `createPushedAuthorizationRequest`. The form body is built automatically:
 * - **Signed**: posts `{ client_id, request }`.
 * - **Unsigned**: posts every field from `authorizationRequest` as flat form
 *   parameters, with object/array values (e.g. `authorization_details`)
 *   JSON-serialised.
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

    const body = isPushedAuthorizationRequestSigned(
      options.pushedAuthorizationRequest,
    )
      ? new URLSearchParams({
          client_id: options.pushedAuthorizationRequest.client_id,
          request: options.pushedAuthorizationRequest.request,
        })
      : toURLSearchParams(
          options.pushedAuthorizationRequest.authorizationRequest,
        );

    const parResponse = await fetch(
      options.pushedAuthorizationRequestEndpoint,
      {
        body,
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

function toURLSearchParams(data: Record<string, unknown>): URLSearchParams {
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
