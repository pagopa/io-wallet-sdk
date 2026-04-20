import { z } from "zod";

import { commonMetadataSchema } from "../metadata/common";
import { swapValidators } from "../metadata/operator/utils/swap-validators";
import { metadataPolicySchema } from "../metadata/policy";

export const createEntity = <T extends string, S extends z.ZodRawShape>({
  additionalValidation = {} as S,
  identifier,
  passThroughUnknownProperties = false,
}: {
  additionalValidation?: S;
  identifier: T;
  passThroughUnknownProperties?: boolean;
}) => {
  const schema = commonMetadataSchema.extend(additionalValidation);
  return {
    identifier,
    policySchema: swapValidators(schema, metadataPolicySchema.optional()),
    schema: passThroughUnknownProperties ? schema.loose() : schema,
  };
};
