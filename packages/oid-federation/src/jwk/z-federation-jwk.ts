import { zJwk } from "@pagopa/io-wallet-utils";
import { z } from "zod";

/**
 * JWK as used in OpenID Federation key sets, where `kid` is REQUIRED
 * so that statements and trust marks can reference the signing key.
 */
export const zFederationJwk = zJwk.extend({
  kid: z.string(),
});

export type FederationJwk = z.infer<typeof zFederationJwk>;

export const zFederationJwkSet = z.looseObject({
  keys: z.array(zFederationJwk),
});

export type FederationJwkSet = z.infer<typeof zFederationJwkSet>;
