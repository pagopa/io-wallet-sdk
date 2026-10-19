import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import { ParsedLoTE } from "../lote";
import { LoTEProfile } from "../lote/constants";
import {
  GetX509CertificateMetadataCallback,
  VerifyX509CertificateChainCallback,
} from "../x509";
import { validateCertificateChainAgainstLoTE } from "../x509/validate-certificate-chain";
import { WRPAC, zWRPAC } from "./z-wrpac";

export interface ValidateWRPACOptions {
  callbacks: {
    getX509CertificateMetadata: GetX509CertificateMetadataCallback;
    verifyX509CertificateChain: VerifyX509CertificateChainCallback;
  };
  /** Validation time. Defaults to the current time. */
  now?: Date;
  /**
   * The certificate chain, starting with the WRPAC, DER encoded in base64.
   * It is usually the `x5c` of the Credential Issuer metadata or of the Request Object.
   */
  wrpacChain: [string, ...string[]];
  /** A Provider of WRPAC LoTE, authenticated with `validateLoTE`. */
  wrpacLote: ParsedLoTE;
}

export interface ValidatedWRPAC {
  /** The Trust Anchor that validated the WRPAC chain. */
  trustAnchor: string;
  /** The validated and parsed WRPAC */
  wrpac: WRPAC;
}

/**
 * Validates a Wallet-Relying Party Access Certificate, as per the IT-Wallet
 * WRPAC validation algorithm based on ETSI TS 119 411-8.
 *
 * The signature of the object carrying the WRPAC (e.g. the Request Object) is
 * not verified. Revocation is checked only by `verifyX509CertificateChain`.
 *
 * @returns The parsed WRPAC and the Trust Anchor that validated its chain.
 * @throws {ValidationError} if the WRPAC content is invalid.
 * @throws {LoTEError} if `wrpacLote` is not a Provider of WRPAC LoTE.
 * @throws {CertificateChainError} if no Trust Anchor validates the chain.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#wallet-relying-party-access-certificate-validation
 */
export async function validateWRPAC(
  options: ValidateWRPACOptions,
): Promise<ValidatedWRPAC> {
  const wrpac = parseWithErrorHandling(
    zWRPAC,
    await options.callbacks.getX509CertificateMetadata(options.wrpacChain[0]),
    "WRPAC schema validation failed",
  );

  const trustAnchor = await validateCertificateChainAgainstLoTE({
    callbacks: options.callbacks,
    chain: options.wrpacChain,
    lote: options.wrpacLote,
    now: options.now,
    profile: LoTEProfile.EUWRPACProvidersList,
    serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
  });

  return { trustAnchor, wrpac };
}
