import { z } from "zod";

export const zAccessTokenRequest = z
  .object({
    // Authorization code flow
    code: z.optional(z.string()),

    code_verifier: z.optional(z.string()),
    grant_type: z.literal("authorization_code").or(z.literal("refresh_token")),

    redirect_uri: z.optional(z.string()),
    // Refresh token grant
    refresh_token: z.optional(z.string()),
  })
  .passthrough()
  .refine(
    ({ code, code_verifier, grant_type, redirect_uri }) =>
      grant_type === "authorization_code" &&
      (!code || !code_verifier || !redirect_uri),
    {
      message: `If 'grant_type' is 'authorization_code', 'code', 'code_verifier' and 'redirect_uri' must be provided`,
    },
  )
  .refine(
    ({ grant_type, refresh_token }) =>
      grant_type === "refresh_token" && !refresh_token,
    {
      message: `If 'grant_type' is 'refresh_token', 'refresh_token' must be provided`,
    },
  );

export type AccessTokenRequest = z.infer<typeof zAccessTokenRequest>;

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
    token_type: z.literal("DPoP"),
  })
  .passthrough();

export type AccessTokenResponse = z.infer<typeof zAccessTokenResponse>;
