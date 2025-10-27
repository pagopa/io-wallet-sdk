import { parseWithErrorHandling } from "@openid4vc/utils";
import z from "zod";

import { JWK } from "../jwk";
import { jsonWebKeySchema } from "../metadata";

export const getUsedJsonWebKey = (
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
) => {
  const validatedHeader = parseWithErrorHandling(
    z
      .object({
        kid: z.string(),
      })
      .passthrough(),
    header,
    "invalid header claims. Should contain a key id",
  );
  const validatedClaims = parseWithErrorHandling(
    z
      .object({
        jwks: z.object({
          keys: z.array(jsonWebKeySchema),
        }),
      })
      .passthrough(),
    claims,
    "Invalid payload claims. Should contain a json web key set",
  );

  // Get the key from the `claims.jwks` by the `header.kid`
  const key = validatedClaims.jwks?.keys.find(
    (key) => key.kid === validatedHeader.kid,
  );

  if (!key) {
    throw new Error(
      `key with id: '${header.kid}' could not be found in the claims`,
    );
  }

  // Fix a @openid-federation bug where x5c is expected to be an array
  const { x5c, ...jwkWithoutX5c } = key;
  const jwk = JWK.parse({
    ...jwkWithoutX5c,
    x5c: [...(x5c ?? [])],
  });

  return jwk;
};
