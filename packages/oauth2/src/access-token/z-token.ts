import { z } from "zod";

import { zJwtHeader, zJwtPayload } from "../common/jwt/z-jwt";

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

export const zAccessTokenResponse = z
  .object({
    access_token: z.string(),
    authorization_details: z
      .array(
        z
          .object({
            credential_configuration_id: z.optional(z.string()),
            credential_identifiers: z.optional(z.array(z.string())),
            type: z.literal("openid_credential"),
          })
          .passthrough(),
      )
      .optional(),
    expires_in: z.optional(z.number().int()),
    refresh_token: z.optional(z.string()),
    token_type: z.union([z.literal("Bearer"), z.literal("DPoP")]),
  })
  .passthrough();

export type AccessTokenResponse = z.infer<typeof zAccessTokenResponse>;

export const zAccessTokenProfileJwtHeader = z
  .object({
    ...zJwtHeader.shape,
    typ: z.enum(["application/at+jwt", "at+jwt"]),
  })
  .passthrough();

export type AccessTokenProfileJwtHeader = z.infer<
  typeof zAccessTokenProfileJwtHeader
>;

export const zAccessTokenProfileJwtPayload = z
  .object({
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
    jti: z.string(),
    nbf: z.number().optional(),
    scope: z.string().optional(),
    sub: z.string(),
  })
  .passthrough();

export type AccessTokenProfileJwtPayload = z.infer<
  typeof zAccessTokenProfileJwtPayload
>;
