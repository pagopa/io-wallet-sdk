import z from "zod";

import {
  zAuthorizationCodeGrantIdentifier,
  zRefreshTokenGrantIdentifier,
} from "../z-grant-type";
import { zPreAuthorizedCodeGrantIdentifier } from "./z-grant-types";

export const zAccessTokenRequestAPTITUDE = z.discriminatedUnion("grant_type", [
  z.object({
    code: z.string().nonempty(),
    code_verifier: z.string().nonempty(),
    grant_type: zAuthorizationCodeGrantIdentifier,
    redirect_uri: z.string().nonempty(),
  }),
  z.object({
    grant_type: zRefreshTokenGrantIdentifier,
    refresh_token: z.string().nonempty(),
    scope: z.string().optional(),
  }),
  z.object({
    grant_type: zPreAuthorizedCodeGrantIdentifier,
    "pre-authorized_code": z.string().nonempty(),
    tx_code: z.string().optional(),
  }),
]);

export type AccessTokenRequestAPTITUDE = z.infer<
  typeof zAccessTokenRequestAPTITUDE
>;

export type PreAuthorizedCodeGrantType = Extract<
  AccessTokenRequestAPTITUDE,
  { grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code" }
>;
