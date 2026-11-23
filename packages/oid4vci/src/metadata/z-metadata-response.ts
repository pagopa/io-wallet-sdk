import {
  itWalletEntityStatementClaimsSchema,
  itWalletMetadataV1_0,
  itWalletMetadataV1_3,
  itWalletMetadataV1_4,
  itWalletMetadataV1_5,
} from "@pagopa/io-wallet-oid-federation";
import {
  zCertificateChain,
  zCompactJwt,
  zJwtHeader,
  zJwtPayload,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

export const zMetadataResponseV1_0 = z.object({
  discoveredVia: z.enum(["federation"]),
  metadata: itWalletMetadataV1_0,
  openid_federation_claims: itWalletEntityStatementClaimsSchema,
});

export const zMetadataResponseV1_3 = z.object({
  /**
   * Entity statement claims of the Authorization Server, present only when the
   * selected authorization server was resolved through a federation entity
   * distinct from the Credential Issuer.
   */
  authorization_server_federation_claims:
    itWalletEntityStatementClaimsSchema.optional(),
  discoveredVia: z.enum(["federation", "oid4vci"]),
  metadata: itWalletMetadataV1_3,
  openid_federation_claims: itWalletEntityStatementClaimsSchema.optional(),
});

export const zMetadataResponseV1_4 = zMetadataResponseV1_3.extend({
  metadata: itWalletMetadataV1_4,
});

export const zSignedMetadataHeaderV1_5 = zJwtHeader.extend({
  alg: zJwtHeader.shape.alg.refine((alg) => !alg.startsWith("HS"), {
    message: "alg value may not be a MAC algorithm",
  }),
  typ: z.literal("openidvci-issuer-metadata+jwt"),
  x5c: zCertificateChain,
});

export const zSignedMetadataPayloadV1_5 = zJwtPayload.extend({
  authorization_servers: z.tuple([z.url()], z.url()).optional(),
  credential_issuer: z.string(),
  iat: z.number().int(),
  sub: z.string(),
});

export const zMetadataResponseV1_5 = z.object({
  discoveredVia: z.enum(["oid4vci"]),
  metadata: itWalletMetadataV1_5,
  signed_metadata: zCompactJwt,
  x5c: zCertificateChain,
});

export const zMetadataResponse = z.union([
  zMetadataResponseV1_0,
  zMetadataResponseV1_3,
  zMetadataResponseV1_4,
  zMetadataResponseV1_5,
]);

export type MetadataResponseV1_0 = z.infer<typeof zMetadataResponseV1_0>;
export type MetadataResponseV1_3 = z.infer<typeof zMetadataResponseV1_3>;
export type MetadataResponseV1_4 = z.infer<typeof zMetadataResponseV1_4>;
export type MetadataResponseV1_5 = z.infer<typeof zMetadataResponseV1_5>;
export type MetadataResponse =
  | MetadataResponseV1_0
  | MetadataResponseV1_3
  | MetadataResponseV1_4
  | MetadataResponseV1_5;

// For intermediate parsing in fallbackDiscovery:
export const zPartialIssuerMetadata = z.looseObject({
  authorization_servers: z.tuple([z.url()], z.url()).optional(),
});
