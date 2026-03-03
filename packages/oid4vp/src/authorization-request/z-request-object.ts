import {
  zAlgValueNotNone,
  zJwk,
  zJwtPayload,
  zSignedAuthorizationRequestJwtHeaderTyp,
} from "@pagopa/io-wallet-oauth2";
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
    dcql_query: z.record(z.string(), z.any()),
    nonce: z.string(),
    request_uri: z.string().url().optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.literal("direct_post.jwt"),
    response_type: z.literal("vp_token"),
    response_uri: z.string().url(),
    scope: z.string().optional(),
    state: z.string(),
    transaction_data: z.array(z.string()).nonempty().optional(),
    transaction_data_hashes_alg: z.array(z.string()).optional(),
    wallet_nonce: z.string().optional(),
  })
  .passthrough()
  .and(
    z.object({
      ...zJwtPayload.shape,
      iss: z.string(),
    }),
  );

export type AuthorizationRequestObject = z.infer<
  typeof zOpenid4vpAuthorizationRequestPayload
>;

const zOpenid4vpAuthorizationRequestHeaderBase = z.object({
  alg: zAlgValueNotNone,
  kid: z.string(),
  typ: zSignedAuthorizationRequestJwtHeaderTyp,
});

export const zOpenid4vpAuthorizationRequestHeaderV1_0 =
  zOpenid4vpAuthorizationRequestHeaderBase
    .extend({
      trust_chain: z.array(z.string()).nonempty(),
    })
    .passthrough();

export type Openid4vpAuthorizationRequestHeaderV1_0 = z.infer<
  typeof zOpenid4vpAuthorizationRequestHeaderV1_0
>;

export const zOpenid4vpAuthorizationRequestHeaderV1_3 =
  zOpenid4vpAuthorizationRequestHeaderBase
    .extend({
      trust_chain: z.array(z.string()).nonempty().optional(),
      x5c: z.array(z.string()).nonempty(),
    })
    .passthrough();

export type Openid4vpAuthorizationRequestHeaderV1_3 = z.infer<
  typeof zOpenid4vpAuthorizationRequestHeaderV1_3
>;

export type Openid4vpAuthorizationRequestHeader =
  | Openid4vpAuthorizationRequestHeaderV1_0
  | Openid4vpAuthorizationRequestHeaderV1_3;
