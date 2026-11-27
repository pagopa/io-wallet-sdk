import {
  type IoWalletSdkConfig,
  ItWalletSpecsVersion,
  MAX_JTI_LENGTH,
  zJwtHeader,
  zJwtPayload,
} from "@pagopa/io-wallet-utils";
import { z } from "zod";

export const zAccessTokenRequest = z.discriminatedUnion("grant_type", [
  z.object({
    code: z.string().nonempty(),
    code_verifier: z.string().nonempty(),
    grant_type: z.literal("authorization_code"),
    redirect_uri: z.string().nonempty(),
  }),
  z.object({
    grant_type: z.literal("refresh_token"),
    refresh_token: z.string().nonempty(),
    scope: z.string().optional(),
  }),
]);

export type AccessTokenRequest = z.infer<typeof zAccessTokenRequest>;

export type AuthorizationCodeGrantType = Extract<
  AccessTokenRequest,
  { grant_type: "authorization_code" }
>;

export type RefreshTokenGrantType = Extract<
  AccessTokenRequest,
  { grant_type: "refresh_token" }
>;

export const zAccessTokenResponse = z.looseObject({
  access_token: z.string(),
  authorization_details: z
    .array(
      z.looseObject({
        credential_configuration_id: z.optional(z.string()),
        credential_identifiers: z.optional(z.array(z.string())),
        type: z.literal("openid_credential"),
      }),
    )
    .optional(),
  expires_in: z.optional(z.number().int()),
  refresh_token: z.optional(z.string()),
  token_type: z.union([z.literal("Bearer"), z.literal("DPoP")]),
});

export type AccessTokenResponse = z.infer<typeof zAccessTokenResponse>;

/**
 * Token Response since IT-Wallet specs 1.4.7 (unchanged in 1.5.0): `token_type`
 * MUST be `DPoP` and `authorization_details` with `credential_identifiers` is REQUIRED.
 */
export const zAccessTokenResponseV1_4 = zAccessTokenResponse.extend({
  authorization_details: z
    .array(
      z.looseObject({
        credential_configuration_id: z.string(),
        credential_identifiers: z.array(z.string()).nonempty(),
        type: z.literal("openid_credential"),
      }),
    )
    .nonempty(),
  token_type: z.literal("DPoP"),
});

export type AccessTokenResponseV1_4 = z.infer<typeof zAccessTokenResponseV1_4>;

export const zAccessTokenResponseV1_5 = zAccessTokenResponseV1_4;
export type AccessTokenResponseV1_5 = AccessTokenResponseV1_4;

/**
 * Selects the Token Response schema for the given configuration. Without a
 * configuration the permissive legacy schema is used.
 */
export function getAccessTokenResponseSchema(
  config?: IoWalletSdkConfig,
): typeof zAccessTokenResponse | typeof zAccessTokenResponseV1_4 {
  return config?.isVersion(ItWalletSpecsVersion.V1_4) ||
    config?.isVersion(ItWalletSpecsVersion.V1_5)
    ? zAccessTokenResponseV1_4
    : zAccessTokenResponse;
}

export const zAccessTokenProfileJwtHeader = z.looseObject({
  ...zJwtHeader.shape,
  typ: z.enum(["application/at+jwt", "at+jwt"]),
});

export type AccessTokenProfileJwtHeader = z.infer<
  typeof zAccessTokenProfileJwtHeader
>;

export const zAccessTokenProfileJwtPayload = z.looseObject({
  ...zJwtPayload.shape,
  aud: z.string(),
  client_id: z.string(),
  cnf: z
    .object({
      jkt: z.string(),
    })
    .optional(),
  exp: z.number(),
  iat: z.number(),
  iss: z.string(),
  jti: z.string().max(MAX_JTI_LENGTH),
  nbf: z.number().optional(),
  scope: z.string().optional(),
  sub: z.string(),
});

export type AccessTokenProfileJwtPayload = z.infer<
  typeof zAccessTokenProfileJwtPayload
>;

export const zRefreshTokenProfileJwtHeader = z.looseObject({
  ...zJwtHeader.shape,
  kid: z.string(),
  typ: z.literal("rt+jwt"),
});

export type RefreshTokenProfileJwtHeader = z.infer<
  typeof zRefreshTokenProfileJwtHeader
>;

export const zRefreshTokenProfileJwtPayload = z.looseObject({
  ...zJwtPayload.shape,
  aud: z.string(),
  client_id: z.string(),
  cnf: z.object({
    jkt: z.string(),
  }),
  exp: z.number().int(),
  iat: z.number().int(),
  iss: z.string(),
  jti: z.string().max(MAX_JTI_LENGTH),
  nbf: z.number().int(),
  sub: z.string(),
});

export type RefreshTokenProfileJwtPayload = z.infer<
  typeof zRefreshTokenProfileJwtPayload
>;
