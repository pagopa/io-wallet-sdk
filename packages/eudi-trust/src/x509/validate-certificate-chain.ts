import { formatError } from "@pagopa/io-wallet-utils";
import { CertificateChainError } from "../errors";
import { LoTEProfile } from "../lote/constants";
import { ParsedLoTE } from "../lote/fetch-and-validate-lote";
import { getTrustAnchors } from "../lote/get-trust-anchors";
import { includesCertificate } from "./certificate";
import {
  GetX509CertificateMetadataCallback,
  VerifyX509CertificateChainCallback,
  X509Chain,
} from "./types";

export interface ValidateCertificateChainOptions {
  callbacks: {
    verifyX509CertificateChain: VerifyX509CertificateChainCallback;
  };
  /** Certificates, end-entity first, DER encoded in base64. */
  chain: X509Chain;
  /** Validation time. Defaults to the current time. */
  now?: Date;
  /** Candidate Trust Anchor certificates, DER encoded in base64. */
  trustAnchors: string[];
  /** An optional prefix to include in the error messages thrown by this function. */
  errorMessagePrefix?: string;
}

/**
 * Validates a certificate chain against a set of candidate Trust Anchors.
 *
 * The chain may include the Trust Anchor as its last certificate, or consist of
 * the Trust Anchor alone. When the anchor is included in the chain and is found
 * among the candidates, it is selected directly without trying the others.
 *
 * The path validation (RFC 5280) and any revocation check are delegated to the
 * `verifyX509CertificateChain` callback.
 *
 * @returns The Trust Anchor that validated the chain.
 * @throws {CertificateChainError} if no Trust Anchor validates the chain.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#x509-certificate-chain-validation-algorithm
 */
export async function validateCertificateChain(
  options: ValidateCertificateChainOptions,
): Promise<string> {
  const { trustAnchors, errorMessagePrefix } = options;

  if (trustAnchors.length === 0) {
    throw new CertificateChainError(
      formatError("No candidate Trust Anchor found", errorMessagePrefix),
      { code: "TRUST_ANCHOR_NOT_FOUND" },
    );
  }

  const [first, ...rest] = options.chain;
  const last = rest.at(-1) ?? first;
  const listedAnchor = trustAnchors.find((trustAnchor) =>
    includesCertificate([trustAnchor], last),
  );

  // When the last certificate in the chain is the Trust Anchor
  // return it immediately if it's the only certificate...
  if (listedAnchor && rest.length === 0) {
    return listedAnchor;
  }

  // ...or use it directly without trying the other candidate anchors.
  const candidateTrustAnchors = listedAnchor ? [listedAnchor] : trustAnchors;

  const chain: X509Chain = listedAnchor
    ? [first, ...rest.slice(0, -1)]
    : options.chain;

  const now = options.now ?? new Date();
  let cause: unknown;
  for (const trustAnchor of candidateTrustAnchors) {
    try {
      if (
        await options.callbacks.verifyX509CertificateChain({
          chain,
          now,
          trustAnchor,
        })
      ) {
        return trustAnchor;
      }
    } catch (error) {
      cause = error;
    }
  }

  throw new CertificateChainError(
    formatError(
      "No candidate Trust Anchor validates the certificate chain",
      errorMessagePrefix,
    ),
    { cause, code: "CERTIFICATE_CHAIN_INVALID" },
  );
}

export interface ValidateCertificateChainAgainstLoTEOptions extends Omit<
  ValidateCertificateChainOptions,
  "callbacks" | "trustAnchors"
> {
  callbacks: {
    getX509CertificateMetadata: GetX509CertificateMetadataCallback;
    verifyX509CertificateChain: VerifyX509CertificateChainCallback;
  };
  /** A LoTE authenticated with `validateLoTE`. */
  lote: ParsedLoTE;
  /** The profile of `lote`. */
  profile: LoTEProfile;
  /** The service whose Trust Anchors are candidates, e.g. `http://uri.etsi.org/19602/SvcType/PID/Issuance`. */
  serviceTypeIdentifier: string;
}

/**
 * Validates a certificate chain against the Trust Anchors published by a LoTE
 * for a given service. Combines `getTrustAnchors` and `validateCertificateChain`.
 *
 * @returns The Trust Anchor that validated the chain.
 * @throws {LoTEError} if the LoTE does not match the expected profile.
 * @throws {CertificateChainError} if no Trust Anchor validates the chain.
 */
export async function validateCertificateChainAgainstLoTE(
  options: ValidateCertificateChainAgainstLoTEOptions,
): Promise<string> {
  const last = options.chain.at(-1) as string;

  const trustAnchors = getTrustAnchors({
    lote: options.lote.document,
    profile: options.profile,
    serviceTypeIdentifier: options.serviceTypeIdentifier,
  });

  // When the last certificate in the chain is a Trust Anchor, the following edge case
  // may occur: A's TA certificate is issued by B, and both A and B appear in the LoTE.
  // Narrowing by A's issuer would retrieve B's TA certificate, excluding A's from the candidates.
  if (includesCertificate(trustAnchors, last)) {
    return validateCertificateChain({ ...options, trustAnchors });
  }

  const { authorityKeyIdentifier, issuerName, issuerOrganizationIdentifier } =
    await options.callbacks.getX509CertificateMetadata(last);

  return validateCertificateChain({
    ...options,
    trustAnchors: getTrustAnchors({
      authorityKeyIdentifier,
      issuerName,
      issuerOrganizationIdentifier,
      lote: options.lote.document,
      profile: options.profile,
      serviceTypeIdentifier: options.serviceTypeIdentifier,
    }),
  });
}
