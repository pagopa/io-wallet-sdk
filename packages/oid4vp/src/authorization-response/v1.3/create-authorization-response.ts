import type {
  CreateAuthorizationResponseOptionsV1_3,
  CreateAuthorizationResponseResult,
} from "../types";

import {
  ClientIdPrefix,
  extractClientIdPrefix,
} from "../../authorization-request/parse-authorization-request";
import { CreateAuthorizationResponseError } from "../../errors";
import { buildJarmResponse } from "../build-jarm-response";

/**
 * Creates an encrypted JARM authorization response for OpenID4VP presentation — v1.0 / v1.3 variant.
 *
 * When the `openid_federation` client_id prefix is used, `client_metadata` is ignored
 * and `rpJwks` is used for JWKS resolution, as required by the Italian specification.
 */
export async function createAuthorizationResponse(
  options: CreateAuthorizationResponseOptionsV1_3,
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

  // When using OpenID Federation, client_metadata may be present in the request
  // but per the Italian specification most of its content should be ignored —
  // use rpJwks for encryption parameters instead.
  const effectiveClientMetadata =
    clientIdPrefix === ClientIdPrefix.OPENID_FEDERATION
      ? undefined
      : clientMetadata;

  const encryptionJwks = effectiveClientMetadata
    ? effectiveClientMetadata.jwks
    : options.rpJwks.jwks;

  const encValuesSupported =
    effectiveClientMetadata?.encrypted_response_enc_values_supported ??
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
