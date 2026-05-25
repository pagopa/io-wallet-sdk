import type {
  CreateAuthorizationResponseOptionsV1_4,
  CreateAuthorizationResponseResult,
} from "../types";

import {
  ClientIdPrefix,
  extractClientIdPrefix,
} from "../../authorization-request/parse-authorization-request";
import { CreateAuthorizationResponseError } from "../../errors";
import { buildJarmResponse } from "../build-jarm-response";

/**
 * Creates an encrypted JARM authorization response for OpenID4VP presentation — v1.4 variant.
 *
 * **v1.4 behavior:** both `encryptionJwks` and `encValuesSupported`
 * are resolved directly from `requestObject.client_metadata`, falling back to `rpJwks`, regardless
 * of the `client_id` prefix. The IT-Wallet spec (RPR-113) permits `client_metadata.jwks` and
 * `encrypted_response_enc_values_supported` to carry request-specific ephemeral encryption keys
 * even when the `openid_federation` prefix is active.
 */
export async function createAuthorizationResponse(
  options: CreateAuthorizationResponseOptionsV1_4,
): Promise<CreateAuthorizationResponseResult> {
  const { requestObject } = options;
  const clientMetadata = requestObject.client_metadata;
  const { prefix: clientIdPrefix } = extractClientIdPrefix(
    requestObject.client_id,
  );

  if (clientIdPrefix === ClientIdPrefix.X509_HASH && !clientMetadata) {
    throw new CreateAuthorizationResponseError(
      "clientMetadata is required when client_id uses x509_hash prefix",
    );
  }

  const encryptionJwks = clientMetadata?.jwks ?? options.rpJwks.jwks;

  const encValuesSupported =
    clientMetadata?.encrypted_response_enc_values_supported ??
    options.rpJwks.encrypted_response_enc_values_supported;

  return buildJarmResponse({
    authorization_encrypted_response_alg:
      options.authorization_encrypted_response_alg,
    authorization_encrypted_response_enc:
      options.authorization_encrypted_response_enc,
    callbacks: options.callbacks,
    encValuesSupported,
    encryptionJwks,
    requestObject: options.requestObject,
    vp_token: options.vp_token,
  });
}
