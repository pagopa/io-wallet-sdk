import { z } from "zod";

import { MetadataMergeStrategy } from "../metadata-merge-strategy";
import { MetadataOrderOfApplication } from "../metadata-order-of-application";
import { createPolicyOperatorSchema } from "../utils";

export const oneOfOperator = createPolicyOperatorSchema({
  canBeCombinedWith: ["default", "essential"],
  key: "one_of",
  mergeStrategy: MetadataMergeStrategy.Intersection,
  operatorJsonValues: [
    z.array(z.string()),
    // TODO: See how we want to we handle the comparison of objects
    // z.array(z.record(z.string().or(z.number()), z.unknown())),
    z.array(z.number()),
  ],
  orderOfApplication: MetadataOrderOfApplication.AfterDefault,
  parameterJsonValues: [
    z.string(),
    // TODO: See how we want to we handle the comparison of objects
    // z.record(z.string().or(z.number()), z.unknown()),
    z.number(),
  ],
});
