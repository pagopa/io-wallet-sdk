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
 * The Trust Anchor must always come from the LoTE and must not be part of the
 * chain (OpenID4VC HAIP section 6.1.1).
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#x509-certificate-chain-validation-algorithm
 */
export async function validateCertificateChain(
  options: ValidateCertificateChainOptions,
): Promise<string> {
  const { chain, trustAnchors } = options;

  if (trustAnchors.length === 0) {
    throw new CertificateChainError("No candidate Trust Anchor found", {
      code: "TRUST_ANCHOR_NOT_FOUND",
    });
  }

  if (
    chain.some((certificate) => includesCertificate(trustAnchors, certificate))
  ) {
    throw new CertificateChainError(
      "The certificate chain must not include the Trust Anchor",
      { code: "TRUST_ANCHOR_IN_CHAIN" },
    );
  }

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
