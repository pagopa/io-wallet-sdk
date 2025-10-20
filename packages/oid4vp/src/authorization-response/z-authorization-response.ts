import z from "zod";

export const zOid4vpAuthorizationResponseResult = z.object({
  redirect_uri: z.string(),
});
