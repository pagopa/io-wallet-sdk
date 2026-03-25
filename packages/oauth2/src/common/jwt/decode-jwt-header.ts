import { Oauth2JwtParseError } from "@openid4vc/oauth2";
import {
  BaseSchema,
  decodeBase64,
  encodeToUtf8String,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import type { InferSchemaOrDefaultOutput } from "./decode-jwt";

import { JwtSigner, zJwtHeader } from "./z-jwt";

export interface DecodeJwtHeaderOptions<
  HeaderSchema extends BaseSchema | undefined,
> {
  /**
   * Schema to use for validating the header. If not provided the
   * default `zJwtHeader` schema will be used
   */
  headerSchema?: HeaderSchema;

  /**
   * The compact encoded jwt
   */
  jwt: string;
}

export interface DecodeJwtHeaderResult<
  HeaderSchema extends BaseSchema | undefined = undefined,
> {
  header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>;
}

export function decodeJwtHeader<
  HeaderSchema extends BaseSchema | undefined = undefined,
>(
  options: DecodeJwtHeaderOptions<HeaderSchema>,
): DecodeJwtHeaderResult<HeaderSchema> {
  const jwtParts = options.jwt.split(".");
  if (jwtParts.length <= 2) {
    throw new Oauth2JwtParseError("Jwt is not a valid jwt, unable to decode");
  }

  const [headerPart] = jwtParts as [string, ...string[]];

  let headerJson: Record<string, unknown>;
  try {
    headerJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(headerPart)),
      "Unable to parse jwt header to JSON",
    );
  } catch (error) {
    throw new Oauth2JwtParseError(
      `Error parsing JWT. ${error instanceof Error ? error.message : ""}`,
    );
  }

  const header = parseWithErrorHandling(
    options.headerSchema ?? zJwtHeader,
    headerJson,
  ) as InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>;

  return {
    header,
  };
}

export function jwtHeaderFromJwtSigner(signer: JwtSigner) {
  if (signer.method === "did") {
    return {
      alg: signer.alg,
      kid: signer.didUrl,
    };
  }

  if (signer.method === "federation") {
    return {
      alg: signer.alg,
      kid: signer.kid,
      trust_chain: signer.trustChain,
    };
  }

  if (signer.method === "jwk") {
    return {
      alg: signer.alg,
      jwk: signer.publicJwk,
    };
  }

  if (signer.method === "x5c") {
    return {
      alg: signer.alg,
      kid: signer.kid,
      x5c: signer.x5c,
    };
  }
  return { alg: signer.alg };
}
