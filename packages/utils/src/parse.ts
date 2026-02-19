import { z } from "zod";

import { ValidationError } from "./errors/errors";

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
