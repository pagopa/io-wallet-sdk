import type { Jwk } from "@pagopa/io-wallet-utils";

/** A chain of at least one X.509 certificate. */
export type X509Chain = [string, ...string[]];

export interface X509CertificateMetadata {
  /** Country code (C) of the Subject Distinguished Name. */
  country?: string;
  /** Whether the Basic Constraints extension marks the certificate as a CA. */
  isCA?: boolean;
  /** `organizationIdentifier` of the Issuer Distinguished Name (ETSI EN 319 412-1 clause 5.1.4). */
  issuerOrganizationIdentifier?: string;
  /** Key Usage extension values, e.g. `digitalSignature`. */
  keyUsage?: string[];
  /** End of the validity period, checked when provided. */
  notAfter?: Date;
  /** Start of the validity period, checked when provided. */
  notBefore?: Date;
  /** Organization (O) values of the Subject Distinguished Name. */
  organizations: string[];
  /** Certificate Policies extension: policy OIDs with their CPS URIs. */
  policies?: { cpsUris: string[]; oid: string }[];
  /** Subject public key, used to verify the signatures made with the certificate. */
  publicJwk: Jwk;
  /** Attributes of the Subject Distinguished Name. */
  subject?: {
    commonName?: string;
    countryName?: string;
    givenName?: string;
    organizationIdentifier?: string;
    organizationName?: string;
    serialNumber?: string;
    surname?: string;
  };
  /** Subject Alternative Name values (RFC 5280 clause 4.2.1.6). */
  subjectAltNames?: {
    emails: string[];
    phoneNumbers: string[];
    uris: string[];
  };
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
  chain: X509Chain;
  now: Date;
  trustAnchor: string;
}) => Promise<boolean> | boolean;
