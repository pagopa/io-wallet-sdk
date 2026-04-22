import { z } from "zod";

import { MetadataMergeStrategy } from "../metadata-merge-strategy";
import { MetadataOrderOfApplication } from "../metadata-order-of-application";
import { createPolicyOperatorSchema } from "../utils/create-policy-operator-schema";

export const addOperator = createPolicyOperatorSchema({
  canBeCombinedWith: ["default", "subset_of", "superset_of", "essential"],
  key: "add",
  mergeStrategy: MetadataMergeStrategy.Union,
  operatorJsonValues: [
    z.array(z.string()),
    // TODO: See how we want to we handle the comparison of objects
    // z.array(z.record(z.string().or(z.number()), z.unknown())),
    z.array(z.number()),
  ],
  orderOfApplication: MetadataOrderOfApplication.AfterValue,
  parameterJsonValues: [
    z.array(z.string()),
    // TODO: See how we want to we handle the comparison of objects
    // z.array(z.record(z.string().or(z.number()), z.unknown())),
    z.array(z.number()),
  ],
});
