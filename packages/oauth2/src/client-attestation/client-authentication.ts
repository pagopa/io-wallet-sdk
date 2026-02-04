import { AuthorizationServerMetadata } from "@openid4vc/oauth2";

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
