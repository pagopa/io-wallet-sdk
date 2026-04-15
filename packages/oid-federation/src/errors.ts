/**
 * Generic error thrown during OID Federation operations
 */
export class OidFederationError extends Error {
  readonly statusCode?: number;
  constructor(
    message: string,
    options?: { statusCode?: number } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "OidFederationError";
    this.statusCode = options?.statusCode;
  }
}

/**
 * Error thrown when trust chain evaluation fails.
 * This includes signature verification failures, expiry checks,
 * structural inconsistencies, and trust anchor binding failures.
 */
export class TrustChainEvaluationError extends OidFederationError {
  constructor(message: string, cause?: unknown) {
    super(message, { cause });
    this.name = "TrustChainEvaluationError";
  }
}
