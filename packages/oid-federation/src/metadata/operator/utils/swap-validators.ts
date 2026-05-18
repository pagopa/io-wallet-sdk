import { z } from "zod";

/**
 * Builds a schema with the same keys as the source object and a replacement validator for each key.
 *
 * @param schema - Source object schema whose keys are preserved.
 * @param newValidator - Validator assigned to every key in the returned schema.
 * @returns New Zod object schema with swapped field validators.
 */
export const swapValidators = <T extends z.ZodRawShape>(
  schema: z.ZodObject<T>,
  newValidator: z.ZodSchema,
): z.ZodObject<Record<string, typeof newValidator>> =>
  z.object(
    Object.keys(schema.shape).reduce(
      (acc, key) => {
        acc[key as keyof typeof acc] = newValidator;
        return acc;
      },
      {} as { [k in keyof T]: z.ZodSchema },
    ),
  );
