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
 * Error thrown by {@link parseAuthorizeRequest} when the passed
 * request object has an invalid signature or unexpected errors
 * are thrown
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

/**
 * Error thrown by {@link createAuthorizationResponse} in case there
 * are unexpected errors.
 */
export class CreateAuthorizationResponseError extends Oid4vpError {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "CreateAuthorizationResponseError";
  }
}
