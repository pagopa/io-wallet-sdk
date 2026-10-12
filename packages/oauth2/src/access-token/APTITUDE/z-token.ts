import z from "zod";

import {
  zAuthorizationCodeTokenRequest,
  zRefreshTokenTokenRequest,
} from "../z-token";
import { zPreAuthorizedCodeGrantIdentifier } from "./z-grant-types";

export const zPreAuthorizedCodeTokenRequest = z.object({
  grant_type: zPreAuthorizedCodeGrantIdentifier,
  "pre-authorized_code": z.string().nonempty(),
  tx_code: z.string().optional(),
});

export const zAccessTokenRequestAPTITUDE = z.discriminatedUnion("grant_type", [
  zAuthorizationCodeTokenRequest,
  zRefreshTokenTokenRequest,
  zPreAuthorizedCodeTokenRequest,
]);

export type AccessTokenRequestAPTITUDE = z.infer<
  typeof zAccessTokenRequestAPTITUDE
>;

export type PreAuthorizedCodeGrantType = Extract<
  AccessTokenRequestAPTITUDE,
  { grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code" }
>;
