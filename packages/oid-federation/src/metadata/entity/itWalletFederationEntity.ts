import { z } from "zod";

import { jsonWebKeySetSchema } from "../../jwk/jwk";
import { createEntity } from "../../utils/create-entity";

export const federationEntityMetadata = createEntity({
  additionalValidation: {
    federation_fetch_endpoint: z.url().optional(),
    federation_historical_keys_endpoint: z.url().optional(),
    federation_list_endpoint: z.url().optional(),
    federation_resolve_endpoint: z.url().optional(),
    federation_trust_mark_endpoint: z.url().optional(),
    federation_trust_mark_list_endpoint: z.url().optional(),
    federation_trust_mark_status_endpoint: z.url().optional(),
  },
  identifier: "federation_entity",
});

export type FederationEntityMetadata = z.input<
  (typeof federationEntityMetadata)["schema"]
>;

/**
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.1.0/en/trust.html#metadata-of-federation-entity-leaves}
 *
 */
export const itWalletFederationEntityMetadata = federationEntityMetadata.schema
  .extend({
    jwks: jsonWebKeySetSchema.optional(),
    tos_uri: z.url().optional(),
  })
  .loose();

export type ItWalletFederationEntityMetadata = z.input<
  typeof itWalletFederationEntityMetadata
>;

export const itWalletFederationEntityIdentifier =
  federationEntityMetadata.identifier;
