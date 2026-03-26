import { Oauth2JwtParseError } from "@openid4vc/oauth2";
import {
  BaseSchema,
  decodeBase64,
  encodeToUtf8String,
  formatError,
  parseWithErrorHandling,
  stringToJsonWithErrorHandling,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { decodeJwtHeader } from "./decode-jwt-header";
import { zJwtHeader, zJwtPayload } from "./z-jwt";

export interface DecodeJwtOptions<
  HeaderSchema extends BaseSchema | undefined,
  PayloadSchema extends BaseSchema | undefined,
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

  /**
   * Schema to use for validating the payload. If not provided the
   * default `zJwtPayload` schema will be used
   */
  payloadSchema?: PayloadSchema;
}

export interface DecodeJwtResult<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
> {
  header: InferSchemaOrDefaultOutput<HeaderSchema, typeof zJwtHeader>;
  payload: InferSchemaOrDefaultOutput<PayloadSchema, typeof zJwtPayload>;
  signature: string;
}

export function decodeJwt<
  HeaderSchema extends BaseSchema | undefined = undefined,
  PayloadSchema extends BaseSchema | undefined = undefined,
>(
  options: DecodeJwtOptions<HeaderSchema, PayloadSchema>,
): DecodeJwtResult<HeaderSchema, PayloadSchema> {
  const jwtParts = options.jwt.split(".");
  if (jwtParts.length !== 3) {
    throw new Oauth2JwtParseError(
      formatError(
        "Unable to decode because Jwt is not a valid!",
        options.errorMessagePrefix,
      ),
    );
  }

  let payloadJson: Record<string, unknown>;
  try {
    const payloadPart = jwtParts[1];
    if (payloadPart === undefined) {
      throw new Oauth2JwtParseError(
        formatError(
          "Unable to decode because Jwt is not a valid!",
          options.errorMessagePrefix,
        ),
      );
    }
    payloadJson = stringToJsonWithErrorHandling(
      encodeToUtf8String(decodeBase64(payloadPart)),
      formatError(
        "Unable to parse jwt payload to JSON",
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

  const signaturePart = jwtParts[2];
  if (signaturePart === undefined) {
    throw new Oauth2JwtParseError(
      formatError(
        "Unable to decode because Jwt is not a valid!",
        options.errorMessagePrefix,
      ),
    );
  }

  const { header } = decodeJwtHeader({
    errorMessagePrefix: options.errorMessagePrefix,
    headerSchema: options.headerSchema,
    jwt: options.jwt,
  });
  const payload = parseWithErrorHandling(
    options.payloadSchema ?? zJwtPayload,
    payloadJson,
    formatError("Invalid JWT payload", options.errorMessagePrefix),
  );

  return {
    header: header as InferSchemaOrDefaultOutput<
      HeaderSchema,
      typeof zJwtHeader
    >,
    payload: payload as InferSchemaOrDefaultOutput<
      PayloadSchema,
      typeof zJwtPayload
    >,
    signature: signaturePart,
  };
}

// Helper type to check if a schema is provided
type IsSchemaProvided<T> = T extends undefined ? false : true;

// Helper type to infer the output type based on whether a schema is provided
export type InferSchemaOrDefaultOutput<
  ProvidedSchema extends BaseSchema | undefined,
  DefaultSchema extends BaseSchema,
> =
  IsSchemaProvided<ProvidedSchema> extends true
    ? ProvidedSchema extends BaseSchema
      ? z.infer<ProvidedSchema>
      : never
    : z.infer<DefaultSchema>;
