import { z } from "zod";

import { MetadataMergeStrategy } from "../metadata-merge-strategy";
import { MetadataOrderOfApplication } from "../metadata-order-of-application";
import { createPolicyOperatorSchema } from "../utils/create-policy-operator-schema";

export const defaultOperator = createPolicyOperatorSchema({
  canBeCombinedWith: ["add", "one_of", "subset_of", "superset_of", "essential"],
  key: "default",
  mergeStrategy: MetadataMergeStrategy.OperatorValuesEqual,
  operatorJsonValues: [
    z.string(),
    z.number(),
    z.boolean(),
    z.record(z.string(), z.string().or(z.number())),
    z.array(z.unknown()),
  ],
  orderOfApplication: MetadataOrderOfApplication.AfterAdd,
  parameterJsonValues: [
    z.string(),
    z.number(),
    z.boolean(),
    z.record(z.string(), z.string().or(z.number())),
    z.array(z.unknown()),
  ],
});
