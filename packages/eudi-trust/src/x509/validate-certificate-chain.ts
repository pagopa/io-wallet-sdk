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
  /** `path`: certificates C_1, ..., C_n, end-entity first, DER encoded in base64. */
  chain: [string, ...string[]];
  now?: Date;
  /** Candidate Trust Anchor certificates, DER encoded in base64. */
  trustAnchors: string[];
}

/**
 * IT-Wallet "X509 Certificate Chain Validation Algorithm": validate `chain`
 * (RFC 5280 section 6) against the first candidate Trust Anchor that validates it,
 * and return that Trust Anchor. Revocation status is not checked yet.
 *
 * Following ETSI TS 119 182-1 (RFC 7515 `x5c`), the chain may include the Trust
 * Anchor: when last, it is stripped before path validation, and a chain made of
 * the Trust Anchor alone is directly trusted, as the signing certificate is
 * listed itself (e.g. ETSI TS 119 475 GEN-5.2.1-03).
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

export interface ValidateLoTECertificateChainOptions extends Omit<
  ValidateCertificateChainOptions,
  "callbacks" | "trustAnchors"
> {
  callbacks: {
    getX509CertificateMetadata: GetX509CertificateMetadataCallback;
  } & ValidateCertificateChainOptions["callbacks"];
  /** A LoTE authenticated with `validateLoTE`. */
  lote: ParsedLoTE;
  profile: LoTEProfile;
  serviceTypeIdentifier: string;
}

/**
 * Validate `chain` against the Trust Anchors published by a LoTE of the given
 * profile, narrowing the candidates by the issuer of the last certificate.
 * Returns the Trust Anchor that validated the chain.
 */
export async function validateLoTECertificateChain(
  options: ValidateLoTECertificateChainOptions,
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
