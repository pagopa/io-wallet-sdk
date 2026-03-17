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
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "WalletProviderError";
    this.cause = cause;
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
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "FetchCredentialResponseError";
    this.cause = cause;
  }
}

/**
 * Error thrown when an unexpected error occurs during credential request parsing.
 */
export class ParseCredentialRequestError extends Oid4vciError {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "ParseCredentialRequestError";
    this.cause = cause;
  }
}

/**
 * Error thrown when metadata fetching fails at all discovery endpoints.
 */
export class FetchMetadataError extends Oid4vciError {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
    this.name = "FetchMetadataError";
  }
}

/**
 * Error thrown when an unexpected error occurs during credential response creation.
 */
export class CreateCredentialResponseError extends Oid4vciError {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "CreateCredentialResponseError";
    this.cause = cause;
  }
}

/**
 * Error thrown when an unexpected error occurs during credential request JWT proof verification.
 */
export class VerifyCredentialRequestJwtProofError extends Oid4vciError {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "VerifyCredentialRequestJwtProofError";
    this.cause = cause;
  }
}

/**
 * Error thrown when an error occurs during key attestation JWT verification.
 */
export class VerifyKeyAttestationJwtError extends Oid4vciError {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "VerifyKeyAttestationJwtError";
    this.cause = cause;
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

/**
 * Error thrown when a credential request is missing the required DPoP proof header.
 */
export class MissingDpopProofError extends Oid4vciError {
  constructor(
    message = "Credential request is missing required 'DPoP' proof header",
  ) {
    super(message);
    this.name = "MissingDpopProofError";
  }
}

/**
 * Error thrown when a credential request has a missing or invalid Authorization header.
 */
export class CredentialAuthorizationHeaderError extends Oid4vciError {
  constructor(
    message = "Credential request is missing required 'Authorization' header with DPoP scheme",
  ) {
    super(message);
    this.name = "CredentialAuthorizationHeaderError";
  }
}
