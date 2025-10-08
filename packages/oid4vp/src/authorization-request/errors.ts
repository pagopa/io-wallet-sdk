/**
 * Error that is thrown when the JWT signature
 * is not verified successfully or other generic
 * errors occur during request object parsing
 */
export class AuthorizationRequestParsingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthorizationRequestParsingError";
  }
}
