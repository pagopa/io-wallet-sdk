import { ValidationError } from "@openid4vc/utils";
import type { z } from "zod";

export const parseWithErrorHandling = <Schema extends z.ZodSchema>(
  schema: Schema,
  data: unknown,
  customErrorMessage?: string
): z.infer<Schema> => {

  try {
    return schema.parse(data)
  } catch (e) {
    const error = e as z.ZodError;
    const errorMessage = customErrorMessage ?? `Error validating schema with data ${JSON.stringify(data)}`
    
    throw new ValidationError(
      `${errorMessage}: ${formattedErrors(error)}`,
    )

  }
}
const formattedErrors = (error: z.ZodError) => error.issues.map(issue => {
  // Joins nested paths with a dot, e.g., ['user', 'name'] -> 'user.name'
  const path = issue.path.join('.');
  const message = issue.message;

  // Example output: "kid: Required"
  return `${path}: ${message}`;
});
