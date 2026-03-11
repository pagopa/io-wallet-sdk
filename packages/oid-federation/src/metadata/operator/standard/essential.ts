import { z } from "zod";

import { MetadataMergeStrategy } from "../metadata-merge-strategy";
import { MetadataOrderOfApplication } from "../metadata-order-of-application";
import { createPolicyOperatorSchema } from "../utils";

export const essentialOperator = createPolicyOperatorSchema({
  canBeCombinedWith: [
    "add",
    "default",
    "one_of",
    "subset_of",
    "superset_of",
    "value",
  ],
  key: "essential",
  mergeStrategy: MetadataMergeStrategy.SuperiorFollowsIfTrue,
  operatorJsonValues: [z.boolean()],
  orderOfApplication: MetadataOrderOfApplication.Last,
  parameterJsonValues: [
    z.string(),
    z.number(),
    z.boolean(),
    z.record(z.string().or(z.number())),
    z.unknown(),
    z.array(z.unknown()),
  ],
});
