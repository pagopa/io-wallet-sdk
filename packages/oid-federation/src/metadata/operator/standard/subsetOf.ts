import { z } from "zod";

import { MetadataMergeStrategy } from "../metadata-merge-strategy";
import { MetadataOrderOfApplication } from "../metadata-order-of-application";
import { createPolicyOperatorSchema } from "../utils/create-policy-operator-schema";

export const subsetOfOperator = createPolicyOperatorSchema({
  canBeCombinedWith: ["add", "default", "superset_of", "essential"],
  key: "subset_of",
  mergeStrategy: MetadataMergeStrategy.Intersection,
  operatorJsonValues: [
    z.array(z.string()),
    // TODO: See how we want to we handle the comparison of objects
    // z.array(z.record(z.string().or(z.number()), z.unknown())),
    z.array(z.number()),
  ],
  orderOfApplication: MetadataOrderOfApplication.AfterOneOf,
  parameterJsonValues: [
    z.array(z.string()),
    // TODO: See how we want to we handle the comparison of objects
    // z.array(z.record(z.string().or(z.number()), z.unknown())),
    z.array(z.number()),
  ],
});
