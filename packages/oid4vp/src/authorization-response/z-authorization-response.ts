import { VpToken } from "@openid4vc/openid4vp";
import z from "zod";

/**
 * Authorization Response payload
 * (the unencrypted content before JARM encrypt)
 */
export interface AuthorizationResponse {
  state: string;
  vp_token: VpToken;
}

export const zOid4vpAuthorizationResponseResult = z.object({
  redirect_uri: z.string().url().optional(),
});

export type Oid4vpAuthorizationResponseResult = z.infer<
  typeof zOid4vpAuthorizationResponseResult
>;
