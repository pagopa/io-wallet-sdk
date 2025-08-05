import { federationEntityMetadata } from "@openid-federation/core";
import { z } from "zod";

export const itWalletFederationEntityMetadata =
  federationEntityMetadata.schema.extend({
    tos_uri: z.string().url().optional(),
  });

export type ItWalletFederationEntityMetadata = z.input<
  typeof itWalletFederationEntityMetadata
>;

export const itWalletFederationEntityIdentifier =
  federationEntityMetadata.identifier;
