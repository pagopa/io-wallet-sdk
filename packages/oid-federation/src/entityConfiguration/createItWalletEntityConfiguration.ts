import type { Jwk } from "@pagopa/io-wallet-utils";

import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";

/**
 * Low-level signing callback used by entity configuration JWT creation.
 *
 * Unlike {@link SignJwtCallback} (which operates on structured JWT header/payload),
 * this callback receives the raw bytes to sign and returns the raw signature bytes,
 * keeping the oid-federation package independent of any higher-level JWT abstraction.
 */
export type SignCallback = (options: {
  jwk: Jwk;
  toBeSigned: Uint8Array;
}) => Promise<Uint8Array>;

import { Buffer } from "buffer";

import { getUsedJsonWebKey } from "../jsonWeb/getUsedJsonWebKey";
import { base64ToBase64URL } from "../utils/encoding";
import {
  ItWalletEntityConfigurationClaimsOptions,
  itWalletEntityConfigurationClaimsSchema,
} from "./itWalletEntityConfigurationClaims";
import {
  EntityConfigurationHeaderOptions,
  entityConfigurationHeaderSchema,
} from "./z-entity-configuration-header";

export interface CreateEntityConfigurationOptions {
  claims: ItWalletEntityConfigurationClaimsOptions;
  header: EntityConfigurationHeaderOptions;
  signJwtCallback: SignCallback;
}

/**
 * Creates a signed OpenID Federation entity configuration JWT.
 *
 * The signing callback is called with the JWK selected by `header.kid` from
 * `claims.jwks.keys` and the compact JWT signing input.
 *
 * @param options - Entity configuration creation options.
 * @param options.claims - Entity configuration claims to sign.
 * @param options.header - Entity configuration JWT header.
 * @param options.signJwtCallback - Callback used to sign the JWT input.
 * @returns Signed entity configuration JWT.
 * @throws {ValidationError} If header or payload validation fails.
 * @throws {Error} If the matching signing JWK cannot be selected or the JWT input cannot be created.
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

function createJsonWebToken(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  signature: Uint8Array,
) {
  const encodedHeader = base64ToBase64URL(
    Buffer.from(JSON.stringify(header)).toString("base64"),
  );
  const encodedPayload = base64ToBase64URL(
    Buffer.from(JSON.stringify(payload)).toString("base64"),
  );

  const encodedSignature = base64ToBase64URL(
    Buffer.from(signature).toString("base64"),
  );

  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

function createJwtSignableInput(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
) {
  if (Object.keys(header).length === 0) {
    throw new Error("Can not create JWT with an empty header");
  }

  if (Object.keys(payload).length === 0) {
    throw new Error("Can not create JWT with an empty payload");
  }

  const encodedHeader = base64ToBase64URL(
    Buffer.from(JSON.stringify(header)).toString("base64"),
  );
  const encodedPayload = base64ToBase64URL(
    Buffer.from(JSON.stringify(payload)).toString("base64"),
  );

  const toBeSignedString = `${encodedHeader}.${encodedPayload}`;

  return new Uint8Array(Buffer.from(toBeSignedString));
}
