import { jsonWebKeySchema as jsonWebKeySchemaWrong } from "@openid-federation/core";
import { z } from "zod";

export const jsonWebKeySchema = jsonWebKeySchemaWrong.extend({
  x5c: z.array(z.string()).optional(),
});
export type JsonWebKey = z.input<typeof jsonWebKeySchema>;

export const jsonWebKeySetSchema = z.object({
  keys: z.array(jsonWebKeySchema),
});
export type jsonWebKeySet = z.infer<typeof jsonWebKeySetSchema>;
