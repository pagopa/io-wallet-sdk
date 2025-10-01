import { zJwtPayload } from '@openid4vc/oauth2'
import {z} from 'zod'

export const zOpenid4vpAuthorizationRequest = z
  .object({
    response_type: z.literal('vp_token'),
    client_id: z.string(),
    response_uri: z.string().url().optional(),
    request_uri: z.string().url().optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.literal("direct_post.jwt"),
    nonce: z.string(),
    wallet_nonce: z.string().optional(),
    scope: z.string().optional(),
    dcql_query: z.record(z.string(), z.any()).optional(),
    state: z.string().optional(),
  })
  .passthrough().and(zJwtPayload)

export type AuthorizationRequestObject = z.infer<typeof zOpenid4vpAuthorizationRequest>