import z from "zod";

import { zJwtHeader, zJwtPayload } from "../common/jwt/z-jwt";

export const zJarAuthorizationRequest = z.looseObject({
  client_id: z.optional(z.string()),
  request: z.optional(z.string()),
  request_uri: z.url().optional(),
});

export type JarAuthorizationRequest = z.infer<typeof zJarAuthorizationRequest>;

export const zJarRequestObjectPayload = z.looseObject({
  ...zJwtPayload.shape,
  client_id: z.string(),
});

export type JarRequestObjectPayload = z.infer<typeof zJarRequestObjectPayload>;

export const zSignedAuthorizationRequestJwtHeaderTyp = z.literal(
  "oauth-authz-req+jwt",
);

export const zJarRequestObjectHeader = z.looseObject({
  ...zJwtHeader.shape,
  typ: zSignedAuthorizationRequestJwtHeaderTyp,
});

export type JarRequestObjectHeader = z.infer<typeof zJarRequestObjectHeader>;

export const signedAuthorizationRequestJwtHeaderTyp =
  zSignedAuthorizationRequestJwtHeaderTyp.value;

const zJwtAuthorizationRequestJwtHeaderTyp = z.literal("jwt");
export const jwtAuthorizationRequestJwtHeaderTyp =
  zJwtAuthorizationRequestJwtHeaderTyp.value;
