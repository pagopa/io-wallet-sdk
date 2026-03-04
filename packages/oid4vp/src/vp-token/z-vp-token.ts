import { z } from "zod";

export const zVpToken = z.record(z.string(), z.array(z.string()).nonempty(), {
  message:
    "vp_token must be an object where each key is a string and each value is a non-empty array of strings.",
});

export type VpToken = z.infer<typeof zVpToken>;
