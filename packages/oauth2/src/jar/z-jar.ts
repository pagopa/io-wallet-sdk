import z from "zod";

import { zJwtPayload } from "../common/jwt/z-jwt";

export const zJarAuthorizationRequest = z
  .object({
    client_id: z.optional(z.string()),
    request: z.optional(z.string()),
    request_uri: z.string().url().optional(),
  })
  .passthrough();

export type JarAuthorizationRequest = z.infer<typeof zJarAuthorizationRequest>;

export const zJarRequestObjectPayload = z
  .object({
    ...zJwtPayload.shape,
    client_id: z.string(),
  })
  .passthrough();

export type JarRequestObjectPayload = z.infer<typeof zJarRequestObjectPayload>;

const zSignedAuthorizationRequestJwtHeaderTyp = z.literal(
  "oauth-authz-req+jwt",
);
export const signedAuthorizationRequestJwtHeaderTyp =
  zSignedAuthorizationRequestJwtHeaderTyp.value;

const zJwtAuthorizationRequestJwtHeaderTyp = z.literal("jwt");
export const jwtAuthorizationRequestJwtHeaderTyp =
  zJwtAuthorizationRequestJwtHeaderTyp.value;
