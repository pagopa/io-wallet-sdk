import { describe, expect, it } from "vitest";

import { oneOfOperator } from "../oneOf";

describe("one_of operator", () => {
  it("accepts arrays of objects as operator values", () => {
    expect(
      oneOfOperator.operatorSchema.safeParse([
        { format: "dc+sd-jwt" },
        { format: "mso_mdoc" },
      ]).success,
    ).toBe(true);
  });

  it("accepts objects as metadata parameter values", () => {
    expect(
      oneOfOperator.parameterSchema.safeParse({
        format: "dc+sd-jwt",
      }).success,
    ).toBe(true);
  });
});
