// An error reason that supports both a string and a generic JSON object
type GenericErrorReason = Record<string, unknown> | string;

/**
 * utility to format a set of attributes into an error message string
 *
 * @example
 * // returns "foo=value bar=(list, item)"
 * serializeAttrs({ foo: "value", bar: ["list", "item"] })
 *
 * @param attrs A key value record set
 * @returns a human-readable serialization of the set
 */
export const serializeAttrs = (
  attrs: Record<string, GenericErrorReason | number | string[] | undefined>,
): string =>
  Object.entries(attrs)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => {
      if (Array.isArray(v)) return [k, `(${v.join(", ")})`];
      if (typeof v !== "string") return [k, JSON.stringify(v)];
      return [k, v];
    })
    .map((_) => _.join("="))
    .join(" ");

/**
 * An error subclass thrown when an HTTP request has a status code different from the one expected.
 */
export class UnexpectedStatusCodeError extends Error {
  code = "ERR_UNEXPECTED_STATUS_CODE";
  reason: GenericErrorReason;
  statusCode: number;

  constructor({
    message,
    reason,
    statusCode,
  }: {
    message: string;
    reason: GenericErrorReason;
    statusCode: number;
  }) {
    super(serializeAttrs({ message, reason, statusCode }));
    this.reason = reason;
    this.statusCode = statusCode;
  }
}
