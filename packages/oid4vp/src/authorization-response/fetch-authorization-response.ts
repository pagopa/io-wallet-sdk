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

import {
  X509CertificateBinding,
  validateCertificateEndpoints,
} from "../authorization-request/validate-certificate-endpoints";
import { FetchAuthorizationResponseError } from "../errors";
import {
  Openid4vpAuthorizationResponseResult,
  zOpenid4vpAuthorizationResponseResult,
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
   * The response_uri field contained in the {@link Openid4vpAuthorizationRequestPayload}
   */
  presentationResponseUri: string;

  /**
   * Optional RP certificate context from the parsed Request Object.
   * When provided, `presentationResponseUri` and the returned `redirect_uri`
   * are checked against the certificate SAN entries through the supplied callback.
   */
  x509Certificate?: {
    binding: X509CertificateBinding;
    leafCertificate: string;
  };
}

/**
 * Sends the {@link Openid4vpAuthorizationResponse} to the response uri provided by the session's
 * {@link Openid4vpAuthorizationRequestPayload} and returns the {@link Openid4vpAuthorizationResponseResult} object
 * containing the redirect_uri at which to continue the presentation
 *
 * @param options {@link FetchAuthorizationResponseOptions}
 * @returns Promise that resolves to the parsed {@link Openid4vpAuthorizationResponseResult}
 * @throws {UnexpectedStatusCodeError} When the server returns a non-200 status code
 * @throws {ValidationError} When the response cannot be parsed or is invalid
 */
export async function fetchAuthorizationResponse(
  options: FetchAuthorizationResponseOptions,
): Promise<Openid4vpAuthorizationResponseResult> {
  try {
    if (options.x509Certificate) {
      await validateCertificateEndpoints({
        callbacks: options.x509Certificate.binding,
        certificate: options.x509Certificate.leafCertificate,
        endpoints: [
          { name: "response_uri", uri: options.presentationResponseUri },
        ],
      });
    }

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
    const parsedAuthorizationResponseResult = parseWithErrorHandling(
      zOpenid4vpAuthorizationResponseResult,
      authorizationResponseResultJson,
    );

    if (options.x509Certificate) {
      await validateCertificateEndpoints({
        callbacks: options.x509Certificate.binding,
        certificate: options.x509Certificate.leafCertificate,
        endpoints: [
          {
            name: "redirect_uri",
            uri: parsedAuthorizationResponseResult.redirect_uri,
          },
        ],
      });
    }

    return parsedAuthorizationResponseResult;
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError ||
      error instanceof FetchAuthorizationResponseError
    ) {
      throw error;
    }
    throw new FetchAuthorizationResponseError(
      `Unexpected error sending authorization response: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
