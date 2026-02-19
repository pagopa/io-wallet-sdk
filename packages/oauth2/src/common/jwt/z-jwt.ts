import z from "zod";

import { Jwk, zJwk } from "../jwk/z-jwk";
import { zAlgValueNotNone } from "../z-common";

export interface JwtSignerDid {
  alg: string;
  didUrl: string;
  /**
   * The key id that should be used for signing. You need to make sure the kid actually matches
   * with the key associated with the didUrl.
   */
  kid?: string;

  method: "did";
}

export interface JwtSignerJwk {
  alg: string;
  /**
   * The key id that should be used for signing. You need to make sure the kid actually matches
   * with the key associated with the jwk.
   *
   * If not provided the kid can also be extracted from the `publicJwk`. Providing it here means the `kid` won't
   * be included in the JWT header.
   */
  kid?: string;
  method: "jwk";

  publicJwk: Jwk;
}

export interface JwtSignerX5c {
  alg: string;
  /**
   * The key id that should be used for signing. You need to make sure the kid actually matches
   * with the key associated with the leaf certificate.
   */
  kid?: string;
  method: "x5c";

  x5c: string[];
}

export interface JwtSignerFederation {
  alg: string;
  /**
   * The key id that should be used for signing. You need to make sure the kid actually matches
   * with a key present in the federation.
   */
  kid: string;
  method: "federation";

  trustChain?: [string, ...string[]];
}

// In case of custom nothing will be added to the header
export interface JwtSignerCustom {
  alg: string;
  /**
   * The key id that should be used for signing.
   */
  kid?: string;

  method: "custom";
}

export type JwtSigner =
  | JwtSignerCustom
  | JwtSignerDid
  | JwtSignerFederation
  | JwtSignerJwk
  | JwtSignerX5c;

export type JwtSignerWithJwk = { publicJwk: Jwk } & JwtSigner;

export type JweEncryptor = {
  /**
   * base64-url encoded apu
   */
  apu?: string;

  /**
   * base64-url encoded apv
   */
  apv?: string;

  enc: string;
} & JwtSignerJwk;

export const zCompactJwt = z
  .string()
  .regex(/^([a-zA-Z0-9-_]+)\.([a-zA-Z0-9-_]+)\.([a-zA-Z0-9-_]+)$/, {
    message: "Not a valid compact jwt",
  });

export const zJwtConfirmationPayload = z
  .object({
    // RFC9449. jwk thumbprint of the dpop public key to which the access token is bound
    jkt: z.string().optional(),

    jwk: zJwk.optional(),
  })
  .passthrough();

export const zJwtPayload = z
  .object({
    aud: z.string().optional(),
    cnf: zJwtConfirmationPayload.optional(),
    exp: z.number().int().optional(),
    iat: z.number().int().optional(),
    iss: z.string().optional(),
    jti: z.string().optional(),
    nbf: z.number().int().optional(),

    nonce: z.string().optional(),

    // Reserved for status parameters
    status: z.record(z.string(), z.any()).optional(),

    // Reserved for OpenID Federation
    trust_chain: z.array(z.string()).nonempty().optional(),
  })
  .passthrough();

export type JwtPayload = z.infer<typeof zJwtPayload>;

export const zJwtHeader = z
  .object({
    alg: zAlgValueNotNone,
    jwk: zJwk.optional(),

    kid: z.string().optional(),
    // Reserved for OpenID Federation
    trust_chain: z.array(z.string()).nonempty().optional(),
    typ: z.string().optional(),

    x5c: z.array(z.string()).optional(),
  })
  .passthrough();

export type JwtHeader = z.infer<typeof zJwtHeader>;
