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

/**
 * An error subclass thrown when an unsupported Italian Wallet specification version is requested.
 *
 * This error is thrown when:
 * - A feature or method is called with a version that it doesn't support
 * - An invalid version identifier is provided
 *
 * @example
 * throw new ItWalletSpecsVersionError(
 *   'createCredentialRequest',
 *   '2.0.0',
 *   ['1.0.2', '1.3.3']
 * );
 * // Error: Feature "createCredentialRequest" does not support version 2.0.0.
 * // Supported versions: 1.0.2, 1.3.3
 */
export class ItWalletSpecsVersionError extends Error {
  public readonly code = "IT_WALLET_SPECS_VERSION_ERROR";

  constructor(
    public readonly feature: string,
    public readonly requestedVersion: string,
    public readonly supportedVersions: readonly string[],
  ) {
    super(
      `Feature "${feature}" does not support version ${requestedVersion}.\n` +
        `Supported versions: ${supportedVersions.join(", ")}`,
    );
    this.name = "ItWalletSpecsVersionError";

    // Maintain proper stack trace for V8 engines (Node.js, Chrome)
    const ErrorConstructor = Error as {
      captureStackTrace?: (target: object, constructor: unknown) => void;
    };
    if (typeof ErrorConstructor.captureStackTrace === "function") {
      ErrorConstructor.captureStackTrace(this, ItWalletSpecsVersionError);
    }
  }
}
