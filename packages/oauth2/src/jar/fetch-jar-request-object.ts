import {
  ContentType,
  type Fetch,
  UnexpectedStatusCodeError,
  createFetcher,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { Oauth2Error } from "../errors";

/**
 * Fetches a JWT-Secured Authorization Request object from a `request_uri`.
 *
 * @param options - Request object fetch options.
 * @param options.fetch - Optional fetch implementation; defaults to the runtime fetch through `createFetcher`.
 * @param options.requestUri - URI hosting the signed authorization request object.
 * @returns Compact JAR request object JWT.
 * @throws {UnexpectedStatusCodeError} If the endpoint does not return HTTP 200.
 * @throws {Oauth2Error} If the request object cannot be fetched.
 */
export async function fetchJarRequestObject(options: {
  fetch?: Fetch;
  requestUri: string;
}): Promise<string> {
  const { fetch, requestUri } = options;

  /**
   * Prioritizes OAuth-specific JWT format, with fallbacks to generic JWT and plain text.
   * Quality values (q) indicate preference: 1.0 (default) > 0.9.
   */
  const JAR_ACCEPT_HEADER = [
    ContentType.OAuthAuthorizationRequestJwt, // Preferred: application/oauth-authz-req+jwt
    `${ContentType.Jwt};q=0.9`, // Fallback: application/jwt
    "text/plain", // Final fallback: text/plain
  ].join(", ");

  const response = await createFetcher(fetch)(requestUri, {
    headers: {
      Accept: JAR_ACCEPT_HEADER,
    },
    method: "GET",
  }).catch(() => {
    throw new Oauth2Error(
      `Fetching request_object from request_uri '${requestUri}' failed`,
    );
  });

  await hasStatusOrThrow(200, UnexpectedStatusCodeError)(response);

  return await response.text();
}
