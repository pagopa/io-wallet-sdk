import z from "zod";

import { zVpToken } from "../vp-token";

export const zOpenid4vpAuthorizationResponse = z.object({
  state: z.string(),
  vp_token: zVpToken,
});

export type Openid4vpAuthorizationResponse = z.infer<
  typeof zOpenid4vpAuthorizationResponse
>;

export const zOpenid4vpAuthorizationResponseResult = z.object({
  redirect_uri: z.string().url().optional(),
});

export type Openid4vpAuthorizationResponseResult = z.infer<
  typeof zOpenid4vpAuthorizationResponseResult
>;
