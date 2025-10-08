/**
 * Custom error thrown when parsing fails
 */
export class Oauth2ParseError extends Error {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = "Oauth2ParseError";
  }
}
