import { zJwtPayload } from "@openid4vc/oauth2";
import { z } from "zod";

/**
 * Zod parser that describes a JWT payload
 * containing an OID4VP Request Object
 */
export const zOpenid4vpAuthorizationRequest = z
  .object({
    client_id: z.string(),
    dcql_query: z.record(z.string(), z.any()).optional(),
    nonce: z.string(),
    request_uri: z.string().url().optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.literal("direct_post.jwt"),
    response_type: z.literal("vp_token"),
    response_uri: z.string().url().optional(),
    scope: z.string().optional(),
    state: z.string(),
    wallet_nonce: z.string().optional(),
  })
  .passthrough()
  .and(zJwtPayload);

export type AuthorizationRequestObject = z.infer<
  typeof zOpenid4vpAuthorizationRequest
>;
