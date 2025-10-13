/**
 * Generic error thrown during Oid4vp operations
 */
export class Oid4vpError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "Oid4vpError";
  }
}

/**
 * Error thrown when parsing of authorization requests fails
 */
export class ParseAuthorizeRequestError extends Oid4vpError {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "ParseAuthorizeRequestError";
  }
}
