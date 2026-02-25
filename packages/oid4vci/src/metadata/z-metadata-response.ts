import {
  itWalletEntityStatementClaimsSchema,
  itWalletMetadataV1_0,
  itWalletMetadataV1_3,
} from "@pagopa/io-wallet-oid-federation";
import { z } from "zod";

export const zMetadataResponseV1_0 = z.object({
  discoveredVia: z.enum(["federation"]),
  metadata: itWalletMetadataV1_0,
  openid_federation_claims: itWalletEntityStatementClaimsSchema,
});

export const zMetadataResponseV1_3 = z.object({
  discoveredVia: z.enum(["federation", "oid4vci"]),
  metadata: itWalletMetadataV1_3,
  openid_federation_claims: itWalletEntityStatementClaimsSchema.optional(),
});

export const zMetadataResponse = z.union([
  zMetadataResponseV1_0,
  zMetadataResponseV1_3,
]);

export type MetadataResponseV1_0 = z.infer<typeof zMetadataResponseV1_0>;
export type MetadataResponseV1_3 = z.infer<typeof zMetadataResponseV1_3>;
export type MetadataResponse = MetadataResponseV1_0 | MetadataResponseV1_3;

// For intermediate parsing in fallbackDiscovery:
export const zPartialIssuerMetadata = z
  .object({
    authorization_servers: z.array(z.string()).optional(),
  })
  .passthrough();
