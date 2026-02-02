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
