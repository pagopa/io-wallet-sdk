import {
  ContentType,
  type Fetch,
  createFetcher,
} from "@pagopa/io-wallet-utils";

import { Oauth2Error } from "../errors";

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

  if (!response.ok) {
    throw new Oauth2Error(
      `Fetching request_object from request_uri '${requestUri}' failed with status code '${response.status}'.`,
    );
  }

  return await response.text();
}
