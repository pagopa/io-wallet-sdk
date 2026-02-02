import { z } from "zod";

export const zAccessTokenRequest = z
  .object({
    // Authorization code flow
    code: z.string().optional(),
    code_verifier: z.string().optional(),
    grant_type: z.literal("authorization_code").or(z.literal("refresh_token")),
    redirect_uri: z.string().optional(),
    // Refresh token grant
    refresh_token: z.string().optional(),
    scope: z.string().optional(),
  })
  .passthrough()
  .superRefine((data, ctx) => {
    if (data.grant_type === "authorization_code") {
      if (!data.code || !data.code_verifier || !data.redirect_uri) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "For 'authorization_code', 'code', 'code_verifier', and 'redirect_uri' are required",
        });
      }

      if (data.scope) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "'scope' parameter is not allowed for 'authorization_code' grant",
        });
      }
    }

    if (data.grant_type === "refresh_token") {
      if (!data.refresh_token) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "For 'refresh_token', 'refresh_token' is required",
        });
      }

      if (data.code || data.code_verifier || data.redirect_uri) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "'code', 'code_verifier', and 'redirect_uri' are not allowed for 'refresh_token' grant",
        });
      }
    }
  });

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
