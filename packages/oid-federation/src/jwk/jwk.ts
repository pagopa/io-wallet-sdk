import { jsonWebKeySchema } from "@openid-federation/core";
import { z } from "zod";

export const jsonWebKeySetSchema = z.object({
  keys: z.array(jsonWebKeySchema),
});
export type jsonWebKeySet = z.infer<typeof jsonWebKeySetSchema>;
