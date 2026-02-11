import {
  AuthorizationServerMetadata,
  CallbackContext,
  HttpMethod,
} from "@openid4vc/oauth2";
import { ContentType, FetchHeaders } from "@pagopa/io-wallet-utils";

import { createClientAttestationPopJwt } from "./client-attestation-pop";
import {
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
} from "./z-client-attestation";

/**
 * Supported OAuth 2.0 client authentication methods.
 */
export const SupportedClientAuthenticationMethod = {
  ClientAttestationJwt: "attest_jwt_client_auth",
  ClientSecretBasic: "client_secret_basic",
  ClientSecretPost: "client_secret_post",
  None: "none",
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
  authorizationServerMetadata: AuthorizationServerMetadata;
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
      SupportedClientAuthenticationMethod.ClientAttestationJwt,
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

/**
 * Options for client authentication
 */
export interface ClientAuthenticationCallbackOptions {
  /**
   * Metadata of the authorization server
   */
  authorizationServerMetadata: AuthorizationServerMetadata;

  /**
   * The body as a JSON object. If content type `x-www-form-urlencoded`
   * is used, it will be encoded after this call.
   *
   * You can modify this object
   */
  body: Record<string, unknown>;

  contentType: ContentType;

  /**
   * Headers for the request. You can modify this object
   */
  headers: FetchHeaders;

  /**
   * http method that will be used
   */
  method: HttpMethod;

  /**
   * URL to which the request will be made
   */
  url: string;
}

/**
 * Callback method to determine the client authentication for a request.
 */
export type ClientAuthenticationCallback = (
  options: ClientAuthenticationCallbackOptions,
) => Promise<void> | void;

/**
 * Anonymous client authentication
 */
export function clientAuthenticationAnonymous(): ClientAuthenticationCallback {
  return () => {
    // No authentication, do nothing
  };
}

export interface ClientAuthenticationClientAttestationJwtOptions {
  callbacks: Pick<CallbackContext, "generateRandom" | "signJwt">;
  clientAttestationJwt: string;
}

/**
 * Client authentication using client attestation JWT.
 * This method adds the client attestation JWT and a proof-of-possession JWT to the request headers.
 */
export function clientAuthenticationClientAttestationJwt(
  options: ClientAuthenticationClientAttestationJwtOptions,
): ClientAuthenticationCallback {
  return async ({ authorizationServerMetadata, headers }) => {
    const clientAttestationPop = await createClientAttestationPopJwt({
      authorizationServer: authorizationServerMetadata.issuer,
      callbacks: options.callbacks,
      clientAttestation: options.clientAttestationJwt,
    });

    headers.set(oauthClientAttestationHeader, options.clientAttestationJwt);
    headers.set(oauthClientAttestationPopHeader, clientAttestationPop);
  };
}
