import { LoTEProfile } from "../lote/constants";
import {
  ValidateLoTECertificateChainOptions,
  validateLoTECertificateChain,
} from "../x509/validate-certificate-chain";

export interface ValidateSignSealCertificateOptions extends Omit<
  ValidateLoTECertificateChainOptions,
  "profile"
> {
  /** PID Providers, Wallet Providers or PuB-EAA Providers LoTE. */
  profile:
    | LoTEProfile.EUPIDProvidersList
    | LoTEProfile.EUPubEAAProvidersList
    | LoTEProfile.EUWalletProvidersList;
}

/**
 * IT-Wallet "EUDIW Attestation Signature Validation": validate the Sign/Seal
 * certificate chain of a PID, Wallet Instance Attestation or PuB-EAA (the `x5c`
 * of an SD-JWT VC, or the `x5chain` of an mdoc) against the Trust Anchors of the
 * LoTE selected by the Attestation type. Returns the Trust Anchor.
 *
 * The Attestation signature, the qualified status of PuB-EAA (Trusted Lists)
 * and the historical keys (`ServiceHistory`) are not checked.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#eudiw-attestation-signature-validation
 */
export function validateSignSealCertificate(
  options: ValidateSignSealCertificateOptions,
): Promise<string> {
  return validateLoTECertificateChain(options);
}
