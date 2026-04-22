import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";
import { Buffer } from "buffer";

import type { SignCallback } from "../utils/types";

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
