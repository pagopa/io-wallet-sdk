import type { X509CertificateMetadata } from "../x509/types";

export const certificateMetadata: X509CertificateMetadata = {
  organizations: [],
  publicJwk: { crv: "P-256", kty: "EC", x: "", y: "" },
};

/** Metadata of the WRPAC "NiScy PID Issuer" of the EUDI Wallet reference issuer. */
export const wrpacMetadata: X509CertificateMetadata = {
  ...certificateMetadata,
  isCA: false,
  keyUsage: ["digitalSignature"],
  policies: [{ cpsUris: [], oid: "0.4.0.194118.1.2" }],
  subject: {
    commonName: "NiScy PID Issuer",
    countryName: "EU",
    organizationIdentifier: "NTREU-123456789",
    organizationName: "NiScy PID Issuer",
  },
  subjectAltNames: {
    emails: [],
    phoneNumbers: [],
    uris: ["https://issuer.eudiw.dev"],
  },
};
