import { z } from "zod";

export const zVpToken = z.record(
  z.string(),
  z.string().or(z.array(z.string()).nonempty()),
  {
    message:
      "vp_token must be an object where each key is a string and each value is a non-empty array of strings (v1.3) or a string (v1.0)",
  },
);

export type VpToken = z.infer<typeof zVpToken>;
