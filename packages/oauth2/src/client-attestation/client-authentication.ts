import {
  type CallbackContext,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  type ClientAuthenticationCallback as UtilsClientAuthenticationCallback,
  type ClientAuthenticationCallbackOptions as UtilsClientAuthenticationCallbackOptions,
} from "@pagopa/io-wallet-utils";

import type { BaseAuthorizationServerMetadata } from "../authorization-server-metadata";

import { createClientAttestationPopJwt } from "./client-attestation-pop";
import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from "./types";

/**
 * Supported OAuth 2.0 client authentication methods.
 */
export const SupportedClientAuthenticationMethod = {
  ClientSecretBasic: "client_secret_basic",
  ClientSecretPost: "client_secret_post",
  None: "none",
  WalletAttestationJwt: "attest_jwt_client_auth",
} as const;

/**
 * Union type of supported client authentication methods.
 */
export type SupportedClientAuthenticationMethod =
  (typeof SupportedClientAuthenticationMethod)[keyof typeof SupportedClientAuthenticationMethod];

/**
 * Options for checking client attestation support.
 */
export interface IsClientAttestationSupportedOptions {
  /** Authorization server metadata containing supported authentication methods. */
  authorizationServerMetadata: BaseAuthorizationServerMetadata;
}

/**
 * Checks whether the authorization server supports client attestation authentication.
 *
 * @param options - Configuration including authorization server metadata
 * @returns Object with `supported` boolean indicating if client attestation is available
 */
export function isClientAttestationSupported(
  options: IsClientAttestationSupportedOptions,
) {
  if (
    !options.authorizationServerMetadata
      .token_endpoint_auth_methods_supported ||
    !options.authorizationServerMetadata.token_endpoint_auth_methods_supported.includes(
      SupportedClientAuthenticationMethod.WalletAttestationJwt,
    )
  ) {
    return {
      supported: false,
    };
  }

  return {
    supported: true,
  };
}

export type ClientAuthenticationCallbackOptions =
  UtilsClientAuthenticationCallbackOptions<BaseAuthorizationServerMetadata>;

export type ClientAuthenticationCallback =
  UtilsClientAuthenticationCallback<ClientAuthenticationCallbackOptions>;

/**
 * Creates a client authentication callback that leaves the request unchanged.
 *
 * @returns Client authentication callback for anonymous requests.
 */
export function clientAuthenticationAnonymous(): ClientAuthenticationCallback {
  return () => {
    // No authentication, do nothing
  };
}

export interface ClientAuthenticationWalletAttestationJwtOptions<
  V extends ItWalletSpecsVersion = ItWalletSpecsVersion,
> {
  callbacks: Pick<CallbackContext, "generateRandom" | "signJwt">;
  config: IoWalletSdkConfig<V>;
  walletAttestationJwt: string;
}

/**
 * Client authentication using wallet attestation JWT.
 * This method adds the wallet attestation JWT and a proof-of-possession JWT to the request headers.
 *
 * @param options - Wallet attestation client authentication options.
 * @param options.callbacks - Random generation and signing callbacks for the PoP JWT.
 * @param options.config - IT-Wallet specification version used to create the PoP JWT.
 * @param options.walletAttestationJwt - Wallet attestation JWT to attach to outgoing requests.
 * @returns Client authentication callback that mutates request headers with attestation values.
 * @throws {Oauth2Error} If the PoP JWT cannot be created.
 */
export function clientAuthenticationWalletAttestationJwt<
  V extends ItWalletSpecsVersion = ItWalletSpecsVersion,
>(
  options: ClientAuthenticationWalletAttestationJwtOptions<V>,
): ClientAuthenticationCallback {
  return async ({ authorizationServerMetadata, headers }) => {
    const clientAttestationPop = await createClientAttestationPopJwt({
      authorizationServer: authorizationServerMetadata.issuer,
      callbacks: options.callbacks,
      clientAttestation: options.walletAttestationJwt,
      config: options.config,
    });

    headers.set(oauthClientAttestationHeader, options.walletAttestationJwt);
    headers.set(oauthClientAttestationPopHeader, clientAttestationPop);
  };
}
