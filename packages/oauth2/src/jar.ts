import {
  ContentType,
  type Fetch,
  createFetcher,
  zHttpsUrl,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { Oauth2Error } from "./errors";
import { CallbackContext } from "./index";

export const zJarAuthorizationRequest = z
  .object({
    client_id: z.optional(z.string()),
    request: z.optional(z.string()),
    request_uri: z.optional(zHttpsUrl),
  })
  .passthrough();

export type JarAuthorizationRequest = z.infer<typeof zJarAuthorizationRequest>;

export function isJarAuthorizationRequest(
  request: JarAuthorizationRequest,
): request is JarAuthorizationRequest {
  return "request" in request || "request_uri" in request;
}

export interface ParsedJarRequestOptions {
  callbacks: Pick<CallbackContext, "fetch">;
  jarRequestParams: JarAuthorizationRequest;
}

export interface ParsedJarRequest {
  authorizationRequestJwt: string;
  sendBy: "reference" | "value";
}

/**
 * Parse a JAR (JWT Secured Authorization Request) request by validating and optionally fetch from uri.
 *
 * @param options - The input parameters
 * @param options.jarRequestParams - The JAR authorization request parameters
 * @param options.callbacks - Context containing the relevant Jose crypto operations
 * @returns An object containing the transmission method ('value' or 'reference') and the JWT request object.
 */
export async function parseJarRequest(
  options: ParsedJarRequestOptions,
): Promise<ParsedJarRequest> {
  const { callbacks } = options;

  const jarRequestParams = {
    ...validateJarRequestParams(options),
    ...options.jarRequestParams,
  } as JarAuthorizationRequest & ReturnType<typeof validateJarRequestParams>;

  const sendBy = jarRequestParams.request ? "value" : "reference";

  const authorizationRequestJwt =
    jarRequestParams.request ??
    (await fetchJarRequestObject({
      fetch: callbacks.fetch,
      requestUri: jarRequestParams.request_uri,
    }));

  return { authorizationRequestJwt, sendBy };
}

export function validateJarRequestParams(options: {
  jarRequestParams: JarAuthorizationRequest;
}) {
  const { jarRequestParams } = options;

  if (jarRequestParams.request && jarRequestParams.request_uri) {
    throw new Oauth2Error(
      "request and request_uri cannot both be present in a JAR request",
    );
  }

  if (!jarRequestParams.request && !jarRequestParams.request_uri) {
    throw new Oauth2Error("request or request_uri must be present");
  }

  return jarRequestParams as (
    | { request: string; request_uri?: never }
    | { request?: never; request_uri: string }
  ) &
    JarAuthorizationRequest;
}

async function fetchJarRequestObject(options: {
  fetch?: Fetch;
  requestUri: string;
}): Promise<string> {
  const { fetch, requestUri } = options;

  const response = await createFetcher(fetch)(requestUri, {
    headers: {
      Accept: `${ContentType.OAuthAuthorizationRequestJwt}, ${ContentType.Jwt};q=0.9, text/plain`,
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
