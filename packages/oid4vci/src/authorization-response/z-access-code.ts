import z from "zod";

export const zAuthorizationResponse = z.object({
  code: z.string(),
  iss: z.string(),
  state: z.string(),
});

export type AuthorizationResponse = z.infer<typeof zAuthorizationResponse>;
