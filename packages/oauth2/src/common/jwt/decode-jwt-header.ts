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

import { zJwtHeader } from "./z-jwt";

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
