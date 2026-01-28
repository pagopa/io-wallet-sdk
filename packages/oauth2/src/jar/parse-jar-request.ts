import { CallbackContext } from "@openid4vc/oauth2";

import { fetchJarRequestObject } from "./fetch-jar-request-object";
import { validateJarRequestParams } from "./validate-jar-request";
import { JarAuthorizationRequest } from "./z-jar";

export interface ParsedJarRequestOptions {
  callbacks: Pick<CallbackContext, "fetch">;
  jarRequestParams: JarAuthorizationRequest;
}

export interface ParsedJarRequest {
  authorizationRequestJwt: string;
  sendBy: "reference" | "value";
}

export function isJarAuthorizationRequest(
  request: JarAuthorizationRequest,
): request is JarAuthorizationRequest {
  return "request" in request || "request_uri" in request;
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
