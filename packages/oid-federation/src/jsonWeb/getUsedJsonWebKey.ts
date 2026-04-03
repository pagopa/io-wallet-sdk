import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import z from "zod";

import { jsonWebKeySetSchema } from "../jwk";

export const getUsedJsonWebKey = (
  header: Record<string, unknown>,
  claims: Record<string, unknown>,
) => {
  const validatedHeader = parseWithErrorHandling(
    z.looseObject({
      kid: z.string(),
    }),
    header,
    "invalid header claims. Should contain a key id",
  );

  const validatedClaims = parseWithErrorHandling(
    z.looseObject({
      jwks: jsonWebKeySetSchema,
    }),
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

  return key;
};
