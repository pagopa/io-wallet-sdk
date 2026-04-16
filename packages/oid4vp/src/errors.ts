/**
 * Generic error thrown during Oid4vp operations
 */
export class Oid4vpError extends Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "Oid4vpError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown by {@link parseAuthorizeRequest} when the passed
 * request object has an invalid signature or unexpected errors
 * are thrown
 */
export class ParseAuthorizeRequestError extends Oid4vpError {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "ParseAuthorizeRequestError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown by {@link fetchAuthorizationResponse}
 */
export class FetchAuthorizationResponseError extends Oid4vpError {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "FetchAuthorizationResponseError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown by {@link createAuthorizationResponse} in case there
 * are unexpected errors.
 */
export class CreateAuthorizationResponseError extends Oid4vpError {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "CreateAuthorizationResponseError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown when request_uri_method parameter has an invalid value.
 * Valid values are "get" or "post" (case-insensitive).
 */
export class InvalidRequestUriMethodError extends Oid4vpError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "InvalidRequestUriMethodError";
  }
}
