import { z } from "zod";

import { jsonWebKeySetSchema } from "../jwk";

export const trustMarkSchema = z.object({
  id: z.string(),
  trust_mark: z.string(),
});

export type TrustMark = z.output<typeof trustMarkSchema>;

export const trustMarkIssuerSchema = z.record(z.string(), z.array(z.string()));

export type TrustMarkIssuer = z.input<typeof trustMarkIssuerSchema>;

export const trustMarkOwnerSchema = z.record(
  z.string(),
  z.object({
    jwks: jsonWebKeySetSchema,
    sub: z.string(),
  }),
);

export type TrustMarkOwner = z.input<typeof trustMarkOwnerSchema>;
