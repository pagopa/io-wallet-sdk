import { z } from "zod";

export const entityConfigurationHeaderSchema = z.looseObject({
  kid: z.string(),
  typ: z.literal("entity-statement+jwt"),
});

export type EntityConfigurationHeaderOptions = z.input<
  typeof entityConfigurationHeaderSchema
>;

export type EntityConfigurationHeader = z.output<
  typeof entityConfigurationHeaderSchema
>;
