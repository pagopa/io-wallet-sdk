import { zJwk, zJwtPayload } from "@pagopa/io-wallet-oauth2";
import { z } from "zod";

export const zVpFormatsSupported = z.record(
  z.string(),
  z
    .object({
      alg_values_supported: z.optional(z.array(z.string())),
    })
    .passthrough(),
);

export type VpFormatsSupported = z.infer<typeof zVpFormatsSupported>;

export const zClientMetadata = z
  .object({
    client_name: z.string().optional(),
    encrypted_response_enc_values_supported: z.array(z.string()).optional(),
    jwks: z.object({ keys: z.array(zJwk) }).passthrough(),
    logo_uri: z.string().url().optional(),
    vp_formats_supported: zVpFormatsSupported,
  })
  .passthrough();

export type ClientMetadata = z.infer<typeof zClientMetadata>;

/**
 * Zod parser that describes a JWT payload
 * containing an OID4VP Request Object
 */
export const zOpenid4vpAuthorizationRequestPayload = z
  .object({
    client_id: z.string(),
    client_metadata: zClientMetadata.optional(),
    dcql_query: z.record(z.string(), z.any()).optional(),
    nonce: z.string(),
    request_uri: z.string().url().optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.literal("direct_post.jwt"),
    response_type: z.literal("vp_token"),
    response_uri: z.string().url().optional(),
    scope: z.string().optional(),
    state: z.string(),
    transaction_data: z.array(z.string()).nonempty().optional(),
    transaction_data_hashes_alg: z.array(z.string()).optional(),
    wallet_nonce: z.string().optional(),
  })
  .passthrough()
  .and(zJwtPayload);

export type AuthorizationRequestObject = z.infer<
  typeof zOpenid4vpAuthorizationRequestPayload
>;

export const zOpenid4vpAuthorizationRequestHeader = z
  .object({
    alg: z.string(),
    kid: z.string().optional(),
    trust_chain: z.array(z.string()).nonempty().optional(),
    typ: z.literal("oauth-authz-req+jwt"),
    x5c: z.array(z.string()).optional(),
  })
  .passthrough();

export type Openid4vpAuthorizationRequestHeader = z.infer<
  typeof zOpenid4vpAuthorizationRequestHeader
>;
