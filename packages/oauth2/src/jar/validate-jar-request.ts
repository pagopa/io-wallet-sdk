import { Oauth2Error } from "../errors";
import { JarAuthorizationRequest } from "./z-jar";

/**
 * Validates that JAR parameters identify exactly one request transmission mode.
 *
 * @param options - Validation options.
 * @param options.jarRequestParams - JAR request parameters to validate.
 * @returns The request URI when the request is sent by reference.
 * @throws {Oauth2Error} If both `request` and `request_uri` are present or both are missing.
 */
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
