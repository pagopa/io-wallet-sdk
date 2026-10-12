/** Base error for EUDI trust operations. Underlying failures are kept in cause. */
export class EudiTrustError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EudiTrustError";
  }
}

/** Input cannot be decoded as the requested trust artifact. */
export class EudiTrustParseError extends EudiTrustError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EudiTrustParseError";
  }
}

/** A list's structure or expected profile does not match its requirements. */
export class EudiTrustProfileError extends EudiTrustError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EudiTrustProfileError";
  }
}

/** A required feature, algorithm or validation constraint is unsupported. */
export class EudiTrustUnsupportedFeatureError extends EudiTrustError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EudiTrustUnsupportedFeatureError";
  }
}

/** The supplied signature does not verify with the selected key. */
export class EudiTrustSignatureError extends EudiTrustError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EudiTrustSignatureError";
  }
}

/** The signer is not authorized by the configured trust source. */
export class EudiTrustUntrustedSignerError extends EudiTrustError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EudiTrustUntrustedSignerError";
  }
}

/** The list is outside its usable update interval. */
export class EudiTrustFreshnessError extends EudiTrustError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EudiTrustFreshnessError";
  }
}

/** No supplied certificate path satisfies the selected anchor and constraints. */
export class EudiTrustCertificatePathError extends EudiTrustError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "EudiTrustCertificatePathError";
  }
}
