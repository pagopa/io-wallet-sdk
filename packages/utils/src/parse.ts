import { z } from "zod";

import { JsonParseError, ValidationError } from "./errors/errors";

export type BaseSchema = z.ZodTypeAny;

const SAFE_STRINGIFY_MAX_LENGTH = 200;

function safeStringify(value: unknown): string {
  try {
    const result = JSON.stringify(value, (_key, val) =>
      typeof val === "bigint" ? `[BigInt: ${val}]` : val,
    );
    if (result === undefined) {
      return String(value);
    }
    return result.length > SAFE_STRINGIFY_MAX_LENGTH
      ? `${result.slice(0, SAFE_STRINGIFY_MAX_LENGTH)}…`
      : result;
  } catch {
    return "[unserializable]";
  }
}

/**
 * Parses data with a Zod schema and throws the SDK `ValidationError` on failure.
 *
 * @param schema - Zod schema used for validation.
 * @param data - Unknown value to parse.
 * @param customErrorMessage - Optional error message used when validation fails.
 * @returns Parsed schema output.
 * @throws {ValidationError} If the value does not satisfy the provided schema.
 */
export function stringToJsonWithErrorHandling(
  value: string,
  errorMessage?: string,
): Record<string, unknown> {
  try {
    return JSON.parse(value) as Record<string, unknown>;
  } catch {
    throw new JsonParseError(
      errorMessage ?? "Unable to parse string to JSON.",
      value,
    );
  }
}

export function parseIfJson<T>(data: T): Record<string, unknown> | T {
  if (typeof data !== "string") {
    return data;
  }

  try {
    return JSON.parse(data) as Record<string, unknown>;
  } catch {
    return data;
  }
}

export function parseWithErrorHandling<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  customErrorMessage?: string,
): z.infer<Schema> {
  const parseResult = schema.safeParse(data);

  if (!parseResult.success) {
    throw new ValidationError(
      customErrorMessage ??
        `Error validating schema with data ${safeStringify(data)}`,
      parseResult.error,
    );
  }

  return parseResult.data;
}

/**
 * Prefixes an error message with optional contextual text.
 *
 * @param message - Base error message.
 * @param prefix - Optional prefix to prepend.
 * @returns Formatted error message.
 */
export function formatError(message: string, prefix?: string): string {
  return prefix ? `${prefix} ${message}` : message;
}
