import { z } from "zod";

import { jsonWebKeySetSchema } from "../../../jwk";

/**
 *
 * {@link https://italia.github.io/eid-wallet-it-docs/releases/1.1.0/en/wallet-provider-metadata.html}
 *
 */
export const itWalletProviderEntityMetadata = z.looseObject({
  jwks: jsonWebKeySetSchema.optional(),
  jwks_uri: z.url().optional(),
  // -- 5.2.1 Extensions for JWK Sets in Entity Metadata
  signed_jwks_uri: z.url().optional(),
});

export type ItWalletProviderEntityMetadata = z.input<
  typeof itWalletProviderEntityMetadata
>;

export const itWalletProviderEntityIdentifier = "wallet_provider";
