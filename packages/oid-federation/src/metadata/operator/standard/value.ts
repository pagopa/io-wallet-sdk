import { z } from "zod";

import { MetadataMergeStrategy } from "../metadata-merge-strategy";
import { MetadataOrderOfApplication } from "../metadata-order-of-application";
import { createPolicyOperatorSchema } from "../utils";

export const valueOperator = createPolicyOperatorSchema({
  canBeCombinedWith: ["essential"],
  key: "value",
  mergeStrategy: MetadataMergeStrategy.OperatorValuesEqual,
  operatorJsonValues: [
    z.string(),
    z.number(),
    z.boolean(),
    z.record(z.string().or(z.number()), z.unknown()),
    z.array(z.unknown()),
    z.null(),
  ],
  orderOfApplication: MetadataOrderOfApplication.First,
  parameterJsonValues: [
    z.string(),
    z.number(),
    z.boolean(),
    z.record(z.string(), z.string().or(z.number())),
    z.array(z.unknown()),
  ],
});
