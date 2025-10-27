import {
  EntityConfigurationHeaderOptions,
  createJsonWebToken,
  createJwtSignableInput,
  entityConfigurationHeaderSchema,
} from "@openid-federation/core";

import { getUsedJsonWebKey } from "../jsonWeb/getUsedJsonWebKey";
import { SignCallback } from "../utils";
import { parseWithErrorHandling } from "../utils/validate";
import {
  ItWalletEntityConfigurationClaimsOptions,
  itWalletEntityConfigurationClaimsSchema,
} from "./itWalletEntityConfigurationClaims";

export interface CreateEntityConfigurationOptions {
  claims: ItWalletEntityConfigurationClaimsOptions;
  header: EntityConfigurationHeaderOptions;
  signJwtCallback: SignCallback;
}

/**
 *
 * Create an entity configuration
 *
 * The signing callback will be called with the `header.kid` value in the `claims.jwks.keys` and a signed JWT will be returned
 *
 */
export const createItWalletEntityConfiguration = async ({
  claims,
  header,
  signJwtCallback,
}: CreateEntityConfigurationOptions) => {
  const validatedHeader = parseWithErrorHandling(
    entityConfigurationHeaderSchema,
    header,
    "invalid header claims provided",
  );
  const validatedClaims = parseWithErrorHandling(
    itWalletEntityConfigurationClaimsSchema,
    claims,
    "invalid payload claims provided",
  );

  const toBeSigned = createJwtSignableInput(header, claims);

  const jwk = getUsedJsonWebKey(validatedHeader, validatedClaims);

  const signature = await signJwtCallback({ jwk, toBeSigned });

  return createJsonWebToken(header, claims, signature);
};
