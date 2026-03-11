import type { z } from "zod";

import type { MetadataMergeStrategy } from "./metadata-merge-strategy";
import type { MetadataOrderOfApplication } from "./metadata-order-of-application";

export interface MetadataOperator<TKey extends string> {
  canBeCombinedWith: string[];
  key: TKey;
  mergeStrategy: MetadataMergeStrategy;
  operatorJsonValues: z.ZodSchema[];
  orderOfApplication: MetadataOrderOfApplication;
  parameterJsonValues: z.ZodSchema[];
}
