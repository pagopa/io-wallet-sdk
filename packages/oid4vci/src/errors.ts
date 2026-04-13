/**
 * Generic error thrown on Oid4vci operations
 */
export class Oid4vciError extends Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "Oid4vciError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown in case the DPoP key passed to the
 * {@link WalletProvider.createItWalletAttestationJwt} method
 * doesn't contain a kid
 */
export class WalletProviderError extends Oid4vciError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "WalletProviderError";
  }
}

/**
 * Error thrown when an unexpected error occurs during nonce request.
 */
export class NonceRequestError extends Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "NonceRequestError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown when an unexpected error occurs during credential response fetching.
 */
export class FetchCredentialResponseError extends Oid4vciError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "FetchCredentialResponseError";
  }
}

/**
 * Error thrown when an unexpected error occurs during credential request parsing.
 */
export class ParseCredentialRequestError extends Oid4vciError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ParseCredentialRequestError";
  }
}

/**
 * Error thrown when metadata fetching fails at all discovery endpoints.
 */
export class FetchMetadataError extends Oid4vciError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "FetchMetadataError";
  }
}

/**
 * Error thrown when an unexpected error occurs during credential response creation.
 */
export class CreateCredentialResponseError extends Oid4vciError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CreateCredentialResponseError";
  }
}

/**
 * Error thrown when an unexpected error occurs during credential request JWT proof verification.
 */
export class VerifyCredentialRequestJwtProofError extends Oid4vciError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "VerifyCredentialRequestJwtProofError";
  }
}

/**
 * Error thrown when an error occurs during key attestation JWT verification.
 */
export class VerifyKeyAttestationJwtError extends Oid4vciError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "VerifyKeyAttestationJwtError";
  }
}

/**
 * Error thrown when an error occurs during credential offer operations.
 * This includes parsing, resolving, validating, and extracting grant details from credential offers.
 */
export class CredentialOfferError extends Oid4vciError {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "CredentialOfferError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown when a credential request is missing the required DPoP proof header.
 */
export class MissingDpopProofError extends Oid4vciError {
  constructor(
    message = "Credential request is missing required 'DPoP' proof header",
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "MissingDpopProofError";
  }
}

/**
 * Error thrown when a credential request has a missing or invalid Authorization header.
 */
export class CredentialAuthorizationHeaderError extends Oid4vciError {
  constructor(
    message = "Credential request is missing required 'Authorization' header with DPoP scheme",
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "CredentialAuthorizationHeaderError";
  }
}
