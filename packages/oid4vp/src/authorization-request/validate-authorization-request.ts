import { InvalidRequestUriMethodError, Oid4vpError } from "../errors";
import { AuthorizationRequestUrlParams } from "./z-authorization-request-url";

/**
 * Validates authorization request URL parameters according to IT-Wallet and OpenID4VP specifications.
 *
 * Validation rules:
 * 1. Exactly one of `request` or `request_uri` must be present (mutual exclusivity)
 * 2. `request_uri_method` must be "get" or "post" (case-insensitive) if present
 * 3. `request_uri_method` can only be used with `request_uri` parameter
 *
 * @param params - Parsed authorization request URL parameters
 * @returns Type-narrowed params ensuring mutual exclusivity
 * @throws {Oid4vpError} When both or neither request/request_uri are present
 * @throws {InvalidRequestUriMethodError} When request_uri_method is not "get" or "post"
 * @throws {Oid4vpError} When request_uri_method is used without request_uri
 */
export function validateAuthorizationRequestParams(
  params: AuthorizationRequestUrlParams,
) {
  // Mutual exclusivity check
  if (params.request && params.request_uri) {
    throw new Oid4vpError(
      "request and request_uri cannot both be present in an authorization request",
    );
  }

  // At least one must be present
  if (!params.request && !params.request_uri) {
    throw new Oid4vpError(
      "Either request or request_uri parameter must be present",
    );
  }

  // Validate request_uri_method if present
  if (params.request_uri_method) {
    const normalizedMethod = params.request_uri_method.toLowerCase();
    if (normalizedMethod !== "get" && normalizedMethod !== "post") {
      throw new InvalidRequestUriMethodError(
        `Invalid request_uri_method: '${params.request_uri_method}'. Must be 'get' or 'post'`,
      );
    }
  }

  // request_uri_method only allowed with request_uri
  if (params.request_uri_method && !params.request_uri) {
    throw new Oid4vpError(
      "request_uri_method can only be used with request_uri parameter",
    );
  }

  // Normalize request_uri_method to lowercase if present
  const normalizedMethod = params.request_uri_method
    ? (params.request_uri_method.toLowerCase() as "get" | "post")
    : undefined;

  return {
    ...params,
    request_uri_method: normalizedMethod,
  } as (
    | {
        request?: never;
        request_uri: string;
        request_uri_method?: "get" | "post";
      }
    | { request: string; request_uri?: never; request_uri_method?: never }
  ) &
    typeof params;
}
