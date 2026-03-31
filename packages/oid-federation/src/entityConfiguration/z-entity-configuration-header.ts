import { z } from "zod";

export const entityConfigurationHeaderSchema = z.looseObject({
  alg: z.string(),
  kid: z.string(),
  typ: z.literal("entity-statement+jwt"),
});

export type EntityConfigurationHeaderOptions = z.input<
  typeof entityConfigurationHeaderSchema
>;

export type EntityConfigurationHeader = z.output<
  typeof entityConfigurationHeaderSchema
>;
