import {
  createJsonWebToken,
  createJwtSignableInput,
  EntityConfigurationHeaderOptions,
  entityConfigurationHeaderSchema,
  getUsedJsonWebKey,
  SignCallback,
} from "@openid-federation/core";
import {
  ItWalletEntityConfigurationClaimsOptions,
  itWalletEntityConfigurationClaimsSchema,
} from "./itWalletEntityConfigurationClaims";
import { parseWithErrorHandling } from "../utils/validate";

export type CreateEntityConfigurationOptions = {
  claims: ItWalletEntityConfigurationClaimsOptions;
  header: EntityConfigurationHeaderOptions;
  signJwtCallback: SignCallback;
};

/**
 *
 * Create an entity configuration
 *
 * The signing callback will be called with the `header.kid` value in the `claims.jwks.keys` and a signed JWT will be returned
 *
 */
export const createItWalletEntityConfiguration = async ({
  header,
  signJwtCallback,
  claims,
}: CreateEntityConfigurationOptions) => {
  const validatedHeader = parseWithErrorHandling(
      entityConfigurationHeaderSchema,
      header,
      'invalid header claims provided'
    )
  const validatedClaims = parseWithErrorHandling(
      itWalletEntityConfigurationClaimsSchema,
      claims,
      'invalid payload claims provided'
    )

  const toBeSigned = createJwtSignableInput(header, claims);

  const jwk = getUsedJsonWebKey(validatedHeader, validatedClaims);

  const signature = await signJwtCallback({ toBeSigned, jwk });

  return createJsonWebToken(header, claims, signature);
};
