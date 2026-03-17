import { z } from "zod";

import { jsonWebKeySetSchema } from "../jwk";

export const commonMetadataSchema = z.object({
  contacts: z.array(z.string()).min(1).optional(),
  homepage_uri: z.url().optional(),
  jwks: jsonWebKeySetSchema.optional(),
  jwks_uri: z.url().optional(),
  logo_uri: z.url().optional(),
  organization_name: z.string().optional(),
  policy_uri: z.url().optional(),
  signed_jwks_uri: z.url().optional(),
});
