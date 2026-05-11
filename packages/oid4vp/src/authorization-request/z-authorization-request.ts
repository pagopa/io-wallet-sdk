import {
  zAlgValueNotNone,
  zCertificateChain,
  zJwtPayload,
  zSignedAuthorizationRequestJwtHeaderTyp,
  zTrustChain,
} from "@pagopa/io-wallet-oauth2";
import { itWalletCredentialVerifierMetadataV1_3 } from "@pagopa/io-wallet-oid-federation";
import { z } from "zod";

/**
 * This schema is a less strict version of {@link itWalletCredentialVerifierMetadataV1_3} because
 * only a subset of the Credential Verifier metadata fields are required in the Request Object.
 * @see https://italia.github.io/eid-wallet-it-docs/releases/1.3.3/en/remote-flow.html#request-object
 */
const zOpenid4vpCredentialVerifierMetadata = itWalletCredentialVerifierMetadataV1_3.partial({
  application_type: true,
  client_id: true,
  client_name: true,
  logo_uri: true,
  request_uris: true,
  response_uris: true,
})

/**
 * Zod parser that describes a JWT payload
 * containing an OID4VP Request Object
 */
export const zOpenid4vpAuthorizationRequestPayload = z
  .looseObject({
    client_id: z.string(),
    client_metadata: zOpenid4vpCredentialVerifierMetadata.optional(),
    dcql_query: z.record(z.string(), z.any()),
    nonce: z.string(),
    request_uri: z.url().optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.literal("direct_post.jwt"),
    response_type: z.literal("vp_token"),
    response_uri: z.url(),
    scope: z.string().optional(),
    state: z.string(),
    transaction_data: z.array(z.string()).nonempty().optional(),
    transaction_data_hashes_alg: z.array(z.string()).optional(),
    wallet_nonce: z.string().optional(),
  })
  .and(
    z.object({
      ...zJwtPayload.shape,
      iss: z.string(),
    }),
  );

export type Openid4vpAuthorizationRequestPayload = z.infer<
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
      trust_chain: zTrustChain,
    })
    .loose();

export type Openid4vpAuthorizationRequestHeaderV1_0 = z.infer<
  typeof zOpenid4vpAuthorizationRequestHeaderV1_0
>;

export const zOpenid4vpAuthorizationRequestHeaderV1_3 =
  zOpenid4vpAuthorizationRequestHeaderBase
    .extend({
      trust_chain: zTrustChain.optional(),
      x5c: zCertificateChain,
    })
    .loose();

export type Openid4vpAuthorizationRequestHeaderV1_3 = z.infer<
  typeof zOpenid4vpAuthorizationRequestHeaderV1_3
>;

export type Openid4vpAuthorizationRequestHeader =
  | Openid4vpAuthorizationRequestHeaderV1_0
  | Openid4vpAuthorizationRequestHeaderV1_3;
