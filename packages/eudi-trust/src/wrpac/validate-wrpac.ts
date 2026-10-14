import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import { LoTEProfile } from "../lote/constants";
import {
  ValidateLoTECertificateChainOptions,
  validateLoTECertificateChain,
} from "../x509/validate-certificate-chain";
import { zWRPAC } from "./z-wrpac";

export type ValidateWRPACOptions = Omit<
  ValidateLoTECertificateChainOptions,
  "profile" | "serviceTypeIdentifier"
>;

/**
 * IT-Wallet "Wallet-Relying Party Access Certificate Validation": validate the
 * chain starting with the WRPAC (e.g. the `x5c` of a signed Request Object)
 * against the Trust Anchors of the `WRPAC/Issuance` service of a Providers of
 * WRPAC LoTE (ETSI TS 119 602 Annex F, Table F.3), then check the WRPAC content
 * (ETSI TS 119 411-8 clause 6.6.1, see `zWRPAC`). Returns the Trust Anchor.
 *
 * The revocation status is not checked.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#wallet-relying-party-access-certificate-validation
 */
export async function validateWRPAC(
  options: ValidateWRPACOptions,
): Promise<string> {
  parseWithErrorHandling(
    zWRPAC,
    await options.callbacks.getX509CertificateMetadata(options.chain[0]),
    "Invalid WRPAC",
  );

  const trustAnchor = await validateLoTECertificateChain({
    ...options,
    profile: LoTEProfile.EUWRPACProvidersList,
    serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
  });

  return trustAnchor;
}
