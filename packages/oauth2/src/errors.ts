/**
 * Generic error thrown on OAuth2 operations
 */
export class Oauth2Error extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "Oauth2Error";
  }
}

/**
 * Custom error thrown when pushed authorization request operations fail
 */
export class PushedAuthorizationRequestError extends Oauth2Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "PushedAuthorizationRequestError";
  }
}
