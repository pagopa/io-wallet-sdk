/**
 * Generic error thrown on OAuth2 operations
 */
export class Oauth2Error extends Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "Oauth2Error";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Custom error thrown when pushed authorization request operations fail
 */
export class PushedAuthorizationRequestError extends Oauth2Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "PushedAuthorizationRequestError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown in case {@link createTokenDPoP} is called without neither a custom jti
 * nor a generateRandom callback or when the signJwt callback throws
 */
export class CreateTokenDPoPError extends Oauth2Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CreateTokenDPoPError";
  }
}

/**
 * Error thrown during MRTD (Machine Readable Travel Document) Proof of Possession operations.
 * Used in eID Substantial Authentication with MRTD Verification flow (IT-Wallet L2+ specification).
 */
export class MrtdPopError extends Oauth2Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "MrtdPopError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Custom error thrown when pushed authorization request operations fail
 */
export class FetchTokenResponseError extends Oauth2Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "FetchTokenResponseError";
    this.statusCode = options?.statusCode;
  }
}

export class CreateTokenResponseError extends Oauth2Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "CreateTokenResponseError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown when an unexpected error occurs during client attestation (wallet attestation) creation.
 */
export class ClientAttestationError extends Oauth2Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ClientAttestationError";
  }
}
