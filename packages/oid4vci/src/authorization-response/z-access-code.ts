import z from "zod";

export const zAccessCode = z.object({
  code: z.string(),
  iss: z.string(),
  state: z.string(),
});

export type AccessCode = z.infer<typeof zAccessCode>;
