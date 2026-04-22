import { z } from "zod";

import { jsonWebKeySetSchema } from "../jwk/jwk";

/**
 * @example https://<federation_authority_domain>/trust_marks/<purpose>/<entity_type>
 */
export const trustMarkUrlSchema = z
  .url()
  .regex(/^https:\/\/[^/]+\/trust_marks\/[^/]+\/[^/]+$/);

export const trustMarkSchema = z.object({
  trust_mark: z.string(),
  trust_mark_type: trustMarkUrlSchema,
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
