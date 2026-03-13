import { zCertificateChain } from "@pagopa/io-wallet-oauth2";
import { z } from "zod";

export const jsonWebKeySchema = z.looseObject({
  alg: z.string().optional(),
  key_ops: z.array(z.string()).optional(),
  kid: z.string(),
  kty: z.string(),
  use: z.string().optional(),
  x5c: zCertificateChain.optional(),
  x5t: z.string().optional(),
  "x5t#S256": z.string().optional(),
  x5u: z.string().optional(),
});

export type JsonWebKey = z.input<typeof jsonWebKeySchema>;

export const jsonWebKeySetSchema = z.object({
  keys: z.array(jsonWebKeySchema),
});

export type jsonWebKeySet = z.infer<typeof jsonWebKeySetSchema>;
