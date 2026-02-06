import z from "zod";

/**
 * Schema for authorization request URL query parameters.
 * Note: `request` contains the signed Request Object JWT, it is NOT a claim inside the Request Object.
 */
export const zAuthorizationRequestUrlParams = z
  .object({
    client_id: z.string(),
    request: z.string().optional(), // JWT containing Request Object (by value)
    request_uri: z.string().url().optional(), // URI to fetch Request Object (by reference)
    request_uri_method: z.string().optional(), // HTTP method for request_uri (validated in business logic)
    state: z.string().optional(), // Optional state parameter
  })
  .passthrough();

export type AuthorizationRequestUrlParams = z.infer<
  typeof zAuthorizationRequestUrlParams
>;
