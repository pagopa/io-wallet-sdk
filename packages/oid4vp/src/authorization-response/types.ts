import type {
  ItWalletCredentialVerifierMetadata,
  ItWalletCredentialVerifierMetadataV1_3,
} from "@pagopa/io-wallet-oid-federation";

import { CallbackContext, Jwk } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { Openid4vpAuthorizationRequestPayload } from "../authorization-request/z-authorization-request";
import { VpToken } from "../vp-token/z-vp-token";
import { Openid4vpAuthorizationResponse } from "./z-authorization-response";

/**
 * Base options shared across all versions of createAuthorizationResponse.
 * Version-specific options extend this with a typed `config` field.
 */
export interface CreateAuthorizationResponseOptions {
  /**
   * JARM encryption algorithm (JWE alg), should be one of the values supported by the verifier's metadata.
   * falls back to "ECDH-ES" if not provided.
   */
  authorization_encrypted_response_alg?: string;

  /**
   * JARM encryption encoding (JWE enc), should be one of the values supported by the verifier's metadata.
   * falls back to "A256GCM" if not provided.
   */
  authorization_encrypted_response_enc?: string;

  /**
   * Callbacks for authorization response generation
   */
  callbacks: Pick<CallbackContext, "encryptJwe" | "generateRandom">;

  /**
   * IT-Wallet specification version config
   */
  config: IoWalletSdkConfig;

  /**
   * Presentation's Request Object
   */
  requestObject: Pick<
    Openid4vpAuthorizationRequestPayload,
    "client_id" | "client_metadata" | "nonce" | "state"
  >;

  /**
   * Relying Party metadata JWKS
   */
  rpJwks: {
    encrypted_response_enc_values_supported?: string[];
  } & Pick<
    ItWalletCredentialVerifierMetadata | ItWalletCredentialVerifierMetadataV1_3,
    "jwks"
  >;

  /**
   * Array containing the vp_tokens of the credentials
   * to present
   */
  vp_token: VpToken;
}

export type CreateAuthorizationResponseOptionsV1_0 = {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_0>;
} & Omit<CreateAuthorizationResponseOptions, "config">;

export type CreateAuthorizationResponseOptionsV1_3 = {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_3>;
} & Omit<CreateAuthorizationResponseOptions, "config">;

export type CreateAuthorizationResponseOptionsV1_4 = {
  config: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
} & Omit<CreateAuthorizationResponseOptions, "config">;

/**
 * Union of all version-specific option types for the version router
 */
export type CreateAuthorizationResponseVersionedOptions =
  | CreateAuthorizationResponseOptionsV1_0
  | CreateAuthorizationResponseOptionsV1_3
  | CreateAuthorizationResponseOptionsV1_4;

/**
 * Result of createAuthorizationResponse function.
 * Contains the generated JARM payload and the encrypted response to send to the verifier.
 */
export interface CreateAuthorizationResponseResult {
  authorizationResponsePayload: Openid4vpAuthorizationResponse;
  jarm: {
    encryptionJwk: Jwk;
    responseJwe: string;
  };
}
