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
 * Error thrown when an unexpected error occurs during credential request parsing.
 */
export class ParseCredentialRequestError extends Oid4vciError {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = "ParseCredentialRequestError";
  }
}

/**
 * Error thrown when metadata fetching fails at all discovery endpoints.
 */
export class FetchMetadataError extends Oid4vciError {
  constructor(message: string, originalError?: unknown) {
    super(message);
    this.cause = originalError;
    this.name = "FetchMetadataError";
  }
}

/**
 * Error thrown when an unexpected error occurs during credential request JWT proof verification.
 */
export class VerifyCredentialRequestJwtProofError extends Oid4vciError {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = "VerifyCredentialRequestJwtProofError";
  }
}

/**
 * Error thrown when an error occurs during credential offer operations.
 * This includes parsing, resolving, validating, and extracting grant details from credential offers.
 */
export class CredentialOfferError extends Oid4vciError {
  constructor(message: string, statusCode?: number) {
    super(message, statusCode);
    this.name = "CredentialOfferError";
  }
}
