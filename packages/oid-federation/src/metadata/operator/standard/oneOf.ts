import { z } from "zod";

import { MetadataMergeStrategy } from "../metadata-merge-strategy";
import { MetadataOrderOfApplication } from "../metadata-order-of-application";
import { createPolicyOperatorSchema } from "../utils/create-policy-operator-schema";

export const oneOfOperator = createPolicyOperatorSchema({
  canBeCombinedWith: ["default", "essential"],
  key: "one_of",
  mergeStrategy: MetadataMergeStrategy.Intersection,
  operatorJsonValues: [
    z.array(z.string()),
    z.array(z.record(z.string(), z.unknown())),
    z.array(z.number()),
  ],
  orderOfApplication: MetadataOrderOfApplication.AfterDefault,
  parameterJsonValues: [
    z.string(),
    z.record(z.string(), z.unknown()),
    z.number(),
  ],
});
