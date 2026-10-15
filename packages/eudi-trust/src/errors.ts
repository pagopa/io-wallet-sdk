export class EudiTrustError extends Error {
  code: string;
  constructor(message: string, options?: { code: string } & ErrorOptions) {
    super(message, options);
    this.code = options?.code ?? "GENERIC_ERROR";
    this.name = "EudiTrustError";
  }
}

export type LoTEErrorCode =
  | "INVALID_BOOTSTRAP"
  | "INVALID_LoTE"
  | "INVALID_LoTE_POINTER"
  | "LoTE_EXPIRED"
  | "LoTE_FETCH_FAILED"
  | "LoTE_FILE_CONFLICT"
  | "LoTE_NOT_YET_VALID"
  | "LoTE_SIGNATURE_VERIFICATION_FAILED"
  | "LoTE_TRAVERSAL_LIMIT"
  | "OJEU_LOCATION_INPUT_NOT_MATCHING_OJEU_LOCATION_IN_LoTE"
  | "PIVOT_i_SIGNATURE_VERIFICATION_FAILED"
  | "PIVOT_i-1_SIGNER_CERT_NOT_AUTHENTICATED_BY_PIVOT_i"
  | "PIVOT_n_SIGNER_CERT_NOT_AUTHENTICATED_BY_OJEU"
  | "UNEXPECTED_LoTE_TYPE";

export class LoTEError extends EudiTrustError {
  constructor(
    message: string,
    options: { code: LoTEErrorCode } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "LoTEError";
  }
}

export type CertificateChainErrorCode =
  | "CERTIFICATE_CHAIN_INVALID"
  | "TRUST_ANCHOR_NOT_FOUND";

export class CertificateChainError extends EudiTrustError {
  constructor(
    message: string,
    options: { code: CertificateChainErrorCode } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "CertificateChainError";
  }
}

export type JAdESErrorCode =
  | "JADES_SIGNATURE_VERIFICATION_FAILED"
  | "JADES_X5T_O_MISMATCH";

export class JAdESError extends EudiTrustError {
  constructor(
    message: string,
    options: { code: JAdESErrorCode } & ErrorOptions,
  ) {
    super(message, options);
    this.name = "JAdESError";
  }
}
