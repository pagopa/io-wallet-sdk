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
 * Error thrown in case the DPoP key passed to the
 * {@link WalletProvider.createItWalletAttestationJwt} method
 * doesn't contain a kid
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
