import {
  federationEntityMetadata,
  jsonWebKeySchema as jsonWebKeySchemaWrong,
} from "@openid-federation/core";
import { z } from "zod";

export const jsonWebKeySchema = jsonWebKeySchemaWrong.extend({
  x5c: z.array(z.string()).optional(),
});
export type JsonWebKey = z.input<typeof jsonWebKeySchema>;

/**
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.1.0/en/trust.html#metadata-of-federation-entity-leaves}
 *
 */
export const itWalletFederationEntityMetadata = federationEntityMetadata.schema
  .extend({
    jwks: z
      .object({
        keys: z.array(jsonWebKeySchema),
      })
      .optional(),
    tos_uri: z.string().url().optional(),
  })
  .passthrough();

export type ItWalletFederationEntityMetadata = z.input<
  typeof itWalletFederationEntityMetadata
>;

export const itWalletFederationEntityIdentifier =
  federationEntityMetadata.identifier;
