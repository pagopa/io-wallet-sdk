import type { MetadataOperator } from "../metadata-operator";

/**
 * Converts a metadata operator definition into the policy operator schema shape.
 *
 * @param operator - Metadata operator definition.
 * @returns Schema descriptor used by metadata policy validation and application.
 */
export const createPolicyOperatorSchema = <TKey extends string>(
  operator: MetadataOperator<TKey>,
) =>
  ({
    /**
     * The key of the operator which is used to identify the operator
     */
    key: operator.key,
    /**
     * The merge strategy of the operator
     */
    mergeStrategy: operator.mergeStrategy,
    /**
     * The operator itself
     */
    operator: operator,
    /**
     * The schema for the operator itself so for essential it is only a boolean
     */
    operatorSchema: operator.operatorJsonValues
      .reduce((acc, schema) => acc.or(schema))
      .optional(),
    /**
     * The order of application of the operator
     */
    orderOfApplication: operator.orderOfApplication,
    /**
     * The schema for the parameter the operator can be applied to so when the policy is targeting federation_entity we can check if the policy can handle that property
     */
    parameterSchema: operator.parameterJsonValues
      .reduce((acc, schema) => acc.or(schema))
      .optional(),
  }) as const;
