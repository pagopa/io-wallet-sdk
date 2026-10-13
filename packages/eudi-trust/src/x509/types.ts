import type { Jwk } from "@pagopa/io-wallet-utils";

export interface X509CertificateMetadata {
  /** Country code (C) of the Subject Distinguished Name. */
  country?: string;
  /** `organizationIdentifier` of the Issuer Distinguished Name (ETSI EN 319 412-1 clause 5.1.4). */
  issuerOrganizationIdentifier?: string;
  /** End of the validity period, checked when provided. */
  notAfter?: Date;
  /** Start of the validity period, checked when provided. */
  notBefore?: Date;
  /** Organization (O) values of the Subject Distinguished Name. */
  organizations: string[];
  /** Subject public key, used to verify the signatures made with the certificate. */
  publicJwk: Jwk;
}

/** Parse a DER certificate encoded in base64, as found in the `x5c` header. */
export type GetX509CertificateMetadataCallback = (
  certificate: string,
) => Promise<X509CertificateMetadata> | X509CertificateMetadata;

/**
 * Validate the certification path `chain` (C_1, ..., C_n, end-entity first)
 * against `trustAnchor` at `now`, as defined in RFC 5280 section 6.
 * The Trust Anchor may be self-signed or not, and is never part of `chain`.
 * All certificates are DER encoded in base64.
 */
export type VerifyX509CertificateChainCallback = (options: {
  chain: [string, ...string[]];
  now: Date;
  trustAnchor: string;
}) => Promise<boolean> | boolean;
