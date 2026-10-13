import { LoTEProfile } from "../lote/constants";
import {
  ValidateLoTECertificateChainOptions,
  validateLoTECertificateChain,
} from "../x509/validate-certificate-chain";

export type ValidateWRPACOptions = Omit<
  ValidateLoTECertificateChainOptions,
  "profile" | "serviceTypeIdentifier"
>;

/**
 * IT-Wallet "Wallet-Relying Party Access Certificate Validation": validate the
 * chain starting with the WRPAC (e.g. the `x5c` of a signed Request Object)
 * against the Trust Anchors of the `WRPAC/Issuance` service of a Providers of
 * WRPAC LoTE (ETSI TS 119 602 Annex F, Table F.3). Returns the Trust Anchor.
 *
 * Only the certification path is validated: the WRPAC content profile
 * (ETSI TS 119 411-8) and the revocation status are not checked.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#wallet-relying-party-access-certificate-validation
 */
export function validateWRPAC(options: ValidateWRPACOptions): Promise<string> {
  return validateLoTECertificateChain({
    ...options,
    profile: LoTEProfile.EUWRPACProvidersList,
    serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
  });
}
