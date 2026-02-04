import { entityConfigurationClaimsSchema } from "@openid-federation/core";
import { itWalletMetadataSchema } from "@pagopa/io-wallet-oid-federation";
import { z } from "zod";

export const zMetadataResponse = z.object({
  discoveredVia: z.enum(["federation", "oid4vci"]),
  metadata: itWalletMetadataSchema,
  openid_federation_claims: entityConfigurationClaimsSchema.optional(),
});

export type MetadataResponse = z.infer<typeof zMetadataResponse>;
