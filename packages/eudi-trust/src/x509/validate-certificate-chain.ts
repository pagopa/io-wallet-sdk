import { CertificateChainError } from "../errors";
import { LoTEProfile } from "../lote/constants";
import { ParsedLoTE } from "../lote/fetch-and-validate-lote";
import { getTrustAnchors } from "../lote/get-trust-anchors";
import { includesCertificate } from "./certificate";
import {
  GetX509CertificateMetadataCallback,
  VerifyX509CertificateChainCallback,
} from "./types";

export interface ValidateCertificateChainOptions {
  callbacks: {
    verifyX509CertificateChain: VerifyX509CertificateChainCallback;
  };
  /** Certificates, end-entity first, DER encoded in base64. */
  chain: [string, ...string[]];
  /** Validation time. Defaults to the current time. */
  now?: Date;
  /** Candidate Trust Anchor certificates, DER encoded in base64. */
  trustAnchors: string[];
}

/**
 * Validates a certificate chain against a set of candidate Trust Anchors, as
 * defined by the IT-Wallet X.509 certificate chain validation algorithm.
 *
 * The chain may include the Trust Anchor as its last certificate, or consist of
 * the Trust Anchor alone.
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
  const { trustAnchors } = options;

  if (trustAnchors.length === 0) {
    throw new CertificateChainError("No candidate Trust Anchor found", {
      code: "TRUST_ANCHOR_NOT_FOUND",
    });
  }

  const [first, ...rest] = options.chain;
  const last = rest.at(-1) ?? first;
  const listedAnchor = trustAnchors.find((trustAnchor) =>
    includesCertificate([trustAnchor], last),
  );

  if (listedAnchor && rest.length === 0) {
    return listedAnchor;
  }

  const chain: [string, ...string[]] = listedAnchor
    ? [first, ...rest.slice(0, -1)]
    : options.chain;

  const now = options.now ?? new Date();
  let cause: unknown;
  for (const trustAnchor of trustAnchors) {
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
    "No candidate Trust Anchor validates the certificate chain",
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
  const [first, ...rest] = options.chain;
  const { issuerOrganizationIdentifier } =
    await options.callbacks.getX509CertificateMetadata(rest.at(-1) ?? first);

  return validateCertificateChain({
    ...options,
    trustAnchors: getTrustAnchors({
      issuerOrganizationIdentifier,
      lote: options.lote.document,
      profile: options.profile,
      serviceTypeIdentifier: options.serviceTypeIdentifier,
    }),
  });
}
