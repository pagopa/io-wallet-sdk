import { AuthorizationServerMetadata } from "@openid4vc/oauth2";

export const SupportedClientAuthenticationMethod = {
  ClientAttestationJwt: "attest_jwt_client_auth",
  ClientSecretBasic: "client_secret_basic",
  ClientSecretPost: "client_secret_post",
  None: "none",
} as const;

export type SupportedClientAuthenticationMethod =
  (typeof SupportedClientAuthenticationMethod)[keyof typeof SupportedClientAuthenticationMethod];

export interface IsClientAttestationSupportedOptions {
  authorizationServerMetadata: AuthorizationServerMetadata;
}

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
