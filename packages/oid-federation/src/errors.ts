/**
 * Generic error thrown during OID Federation operations
 */
export class OidFederationError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "OidFederationError";
  }
}

/**
 * Error thrown when trust chain evaluation fails.
 * This includes signature verification failures, expiry checks,
 * structural inconsistencies, and trust anchor binding failures.
 */
export class TrustChainEvaluationError extends OidFederationError {
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "TrustChainEvaluationError";
    this.cause = cause;
  }
}
