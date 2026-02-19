import { z } from "zod";

import { ValidationError } from "./errors/errors";

export type BaseSchema = z.ZodTypeAny;

export function parseWithErrorHandling<Schema extends BaseSchema>(
  schema: Schema,
  data: unknown,
  customErrorMessage?: string,
): z.infer<Schema> {
  const parseResult = schema.safeParse(data);

  if (!parseResult.success) {
    throw new ValidationError(
      customErrorMessage ??
        `Error validating schema with data ${JSON.stringify(data)}`,
      parseResult.error,
    );
  }

  return parseResult.data;
}
