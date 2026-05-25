import { Oauth2JwtParseError } from "@openid4vc/oauth2";
import {
  BaseSchema,
  decodeBase64,
  encodeToUtf8String,
  formatError,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import type { InferSchemaOrDefaultOutput } from "./decode-jwt";

import { JwtSigner, zJwtHeader } from "./z-jwt";

export interface DecodeJwtHeaderOptions<
  HeaderSchema extends BaseSchema | undefined,
> {
  /**
   * Optional prefix for error messages thrown during decoding, to provide more context on where the error occurred
   */
  errorMessagePrefix?: string;

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

/**
 * Decodes and validates the header of a compact JWT.
 *
 * This helper does not verify the JWT signature or parse the payload.
 *
 * @param options - Header decode options.
 * @param options.errorMessagePrefix - Optional context prefix for thrown parse/validation errors.
 * @param options.headerSchema - Optional schema for the JWT header; defaults to `zJwtHeader`.
 * @param options.jwt - Compact JWT to decode.
 * @returns Decoded and schema-validated JWT header.
 * @throws {Oauth2JwtParseError} If the JWT shape or header JSON is invalid.
 * @throws {ValidationError} If header schema validation fails.
 */
export function decodeJwtHeader<
  HeaderSchema extends BaseSchema | undefined = undefined,
>(
  options: DecodeJwtHeaderOptions<HeaderSchema>,
): DecodeJwtHeaderResult<HeaderSchema> {
  const jwtParts = options.jwt.split(".");
  if (jwtParts.length <= 2) {
    throw new Oauth2JwtParseError(
      formatError(
        "Unable to decode because Jwt is not a valid!",
        options.errorMessagePrefix,
      ),
    );
  }

  const [headerPart] = jwtParts as [string, ...string[]];

  let headerJson: Record<string, unknown>;
  try {
    headerJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(headerPart)),
      formatError(
        "Unable to parse jwt header to JSON",
        options.errorMessagePrefix,
      ),
    );
  } catch (error) {
    throw new Oauth2JwtParseError(
      formatError(
        `Error parsing JWT. ${error instanceof Error ? error.message : ""}`,
        options.errorMessagePrefix,
      ),
    );
  }

  const header = parseWithErrorHandling(
    options.headerSchema ?? zJwtHeader,
    headerJson,
    formatError("Invalid JWT header", options.errorMessagePrefix),
  ) as InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>;

  return {
    header,
  };
}

/**
 * Builds a JWT header from an SDK signer descriptor.
 *
 * @param signer - Signer descriptor used by SDK signing callbacks.
 * @returns Header fields required by the signer method.
 */
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
      trust_chain: signer.trustChain,
      x5c: signer.x5c,
    };
  }
  return { alg: signer.alg };
}
