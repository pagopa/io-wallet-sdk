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

/**
 * Error thrown in case {@link createTokenDPoP} is called without neither a custom jti
 * nor a generateRandom callback or when the signJwt callback throws
 */
export class CreateTokenDPoPError extends Oauth2Error {
  constructor(message: string) {
    super(message);
    this.name = "CreateTokenDPoPError";
  }
}

/**
 * Custom error thrown when pushed authorization request operations fail
 */
export class FetchTokenResponseError extends Oauth2Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "fetchTokenResponseError";
  }
}
