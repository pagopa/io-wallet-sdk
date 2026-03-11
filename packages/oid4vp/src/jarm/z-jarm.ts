import { zJwtHeader, zJwtPayload } from "@pagopa/io-wallet-oauth2";
import { z } from "zod";

export const zJarmHeader = z.object({
  ...zJwtHeader.shape,
  apu: z.string().optional(),
  apv: z.string().optional(),
  kid: z.string(),
});

export type JarmHeader = z.infer<typeof zJarmHeader>;

export const zEncryptedJarmHeader = z.object({
  ...zJwtHeader.shape,
  apu: z.string().optional(),
  apv: z.string().optional(),
  enc: z.string().optional(),
  kid: z.string(),
});

export type EncryptedJarmHeader = z.infer<typeof zEncryptedJarmHeader>;

export const zJarmAuthorizationResponse = z.looseObject({
  /**
   * iss: The issuer URL of the authorization server that created the response
   * aud: The client_id of the client the response is intended for
   * exp: The expiration time of the JWT. A maximum JWT lifetime of 10 minutes is RECOMMENDED.
   */
  ...zJwtPayload.shape,
  ...zJwtPayload.pick({ aud: true, exp: true, iss: true }).required().shape,
  state: z.optional(z.string()),
});

export type JarmAuthorizationResponse = z.infer<
  typeof zJarmAuthorizationResponse
>;

export const zJarmAuthorizationResponseEncryptedOnly = z.looseObject({
  ...zJwtPayload.shape,
  state: z.optional(z.string()),
});

export type JarmAuthorizationResponseEncryptedOnly = z.infer<
  typeof zJarmAuthorizationResponseEncryptedOnly
>;
