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
 * Error thrown by {@link fetchAuthorizationResponse}
 */
export class FetchAuthrorizationResponseError extends Oid4vpError {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "FetchAuthrorizationResponseError";
  }
}
