import { zItwSupportedSignatureAlg } from "@pagopa/io-wallet-utils";
import { z } from "zod";

export const entityConfigurationHeaderSchema = z.looseObject({
  /* 
    For the moment the italian specification doesn't restrict algorithms
    for signing the trust chain to a subset of the general accepted ones
  */
  alg: zItwSupportedSignatureAlg,
  kid: z.string(),
  typ: z.literal("entity-statement+jwt"),
});

export type EntityConfigurationHeaderOptions = z.input<
  typeof entityConfigurationHeaderSchema
>;

export type EntityConfigurationHeader = z.output<
  typeof entityConfigurationHeaderSchema
>;
