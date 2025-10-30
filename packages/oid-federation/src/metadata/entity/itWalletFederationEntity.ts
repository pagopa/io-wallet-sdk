import { federationEntityMetadata } from "@openid-federation/core";
import { z } from "zod";

import { jsonWebKeySetSchema } from "../../jwk/jwk";

/**
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.1.0/en/trust.html#metadata-of-federation-entity-leaves}
 *
 */
export const itWalletFederationEntityMetadata = federationEntityMetadata.schema
  .extend({
    jwks: jsonWebKeySetSchema.optional(),
    tos_uri: z.string().url().optional(),
  })
  .passthrough();

export type ItWalletFederationEntityMetadata = z.input<
  typeof itWalletFederationEntityMetadata
>;

export const itWalletFederationEntityIdentifier =
  federationEntityMetadata.identifier;
