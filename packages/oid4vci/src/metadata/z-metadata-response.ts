import {
  itWalletEntityStatementClaimsSchema,
  itWalletMetadataV1_3,
} from "@pagopa/io-wallet-oid-federation";
import { z } from "zod";

export const zMetadataResponse = z.object({
  discoveredVia: z.enum(["federation", "oid4vci"]),
  metadata: itWalletMetadataV1_3,
  openid_federation_claims: itWalletEntityStatementClaimsSchema.optional(),
});

export type MetadataResponse = z.infer<typeof zMetadataResponse>;

// For intermediate parsing in fallbackDiscovery:
export const zPartialIssuerMetadata = z
  .object({
    authorization_servers: z.array(z.string()).optional(),
  })
  .passthrough();
