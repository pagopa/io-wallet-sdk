import {
  ItWalletSpecsVersion,
  createVersionDispatcher,
} from "@pagopa/io-wallet-utils";

import type {
  CreateAuthorizationResponseOptionsV1_3,
  CreateAuthorizationResponseOptionsV1_4,
  CreateAuthorizationResponseResult,
  CreateAuthorizationResponseVersionedOptions,
} from "./types";

import * as V1_3 from "./v1.3/create-authorization-response";
import * as V1_4 from "./v1.4/create-authorization-response";

export type {
  CreateAuthorizationResponseOptionsV1_0,
  CreateAuthorizationResponseOptionsV1_3,
  CreateAuthorizationResponseOptionsV1_4,
  CreateAuthorizationResponseResult,
  CreateAuthorizationResponseVersionedOptions,
} from "./types";

const dispatchCreateAuthorizationResponse = createVersionDispatcher<
  CreateAuthorizationResponseVersionedOptions,
  Promise<CreateAuthorizationResponseResult>
>({
  [ItWalletSpecsVersion.V1_0]: (o) =>
    // V1_0 shares the v1.3 response logic — JWKS / enc resolution is identical.
    V1_3.createAuthorizationResponse(
      o as CreateAuthorizationResponseOptionsV1_3,
    ),
  [ItWalletSpecsVersion.V1_3]: (o) =>
    V1_3.createAuthorizationResponse(
      o as CreateAuthorizationResponseOptionsV1_3,
    ),
  [ItWalletSpecsVersion.V1_4]: (o) =>
    V1_4.createAuthorizationResponse(
      o as CreateAuthorizationResponseOptionsV1_4,
    ),
});

/**
 * Creates an encrypted JARM authorization response for OpenID4VP presentation.
 *
 * Routes to the version-specific implementation based on `config.itWalletSpecsVersion`.
 *
 * **Version differences:**
 * - v1.0 / v1.3: When `openid_federation` client_id prefix is used, `client_metadata`
 *   is ignored and `rpJwks` is used for JWKS resolution.
 * - v1.4: `client_metadata.jwks` is used directly when present, regardless of
 *   the `client_id` prefix, falling back to `rpJwks.jwks`.
 *
 * @throws {CreateAuthorizationResponseError} If response generation or encryption fails
 */
export async function createAuthorizationResponse(
  options: CreateAuthorizationResponseVersionedOptions,
): Promise<CreateAuthorizationResponseResult> {
  return dispatchCreateAuthorizationResponse(options);
}
