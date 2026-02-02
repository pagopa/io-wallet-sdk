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
  .superRefine((data, ctx) => {
    if (data.grant_type === "authorization_code") {
      if (!data.code || !data.code_verifier || !data.redirect_uri) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            "For 'authorization_code', 'code', 'code_verifier', and 'redirect_uri' are required",
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
