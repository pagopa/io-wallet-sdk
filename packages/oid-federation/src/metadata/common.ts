import { zJwkSet } from "@pagopa/io-wallet-utils";
import { z } from "zod";

export const commonMetadataSchema = z.object({
  contacts: z.array(z.string()).min(1).optional(),
  homepage_uri: z.url().optional(),
  jwks: zJwkSet.optional(),
  jwks_uri: z.url().optional(),
  logo_uri: z.url().optional(),
  organization_name: z.string().optional(),
  policy_uri: z.url().optional(),
  signed_jwks_uri: z.url().optional(),
});
