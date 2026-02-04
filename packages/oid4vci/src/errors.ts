/**
 * Generic error thrown on Oid4vci operations
 */
export class Oid4vciError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "Oid4vciError";
  }
}

/**
 * Error thrown in case the DPoP key passed to the
 * {@link WalletProvider.createItWalletAttestationJwt} method
 * doesn't contain a kid
 */
export class WalletProviderError extends Oid4vciError {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = "WalletProviderError";
  }
}

/**
 * Error thrown when an unexpected error occurs during nonce request.
 */
export class NonceRequestError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "NonceRequestError";
  }
}

/**
 * Error thrown when an unexpected error occurs during credential response fetching.
 */
export class FetchCredentialResponseError extends Oid4vciError {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = "FetchCredentialResponseError";
  }
}

/**
 * Error thrown when metadata fetching fails at all discovery endpoints.
 */
export class FetchMetadataError extends Oid4vciError {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = "FetchMetadataError";
  }
}
