import { parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import { LoTEProfile } from "../lote/constants";
import { validateLoTECertificateChain } from "../x509/validate-certificate-chain";
import { zWRPAC } from "./z-wrpac";
import {
  GetX509CertificateMetadataCallback,
  VerifyX509CertificateChainCallback,
} from "../x509";
import { ParsedLoTE } from "../lote";

export type ValidateWRPACOptions = {
  /**
   * The WRPAC certificate chain. In the simplest case, this chain only contains the WRPAC.
   *
   * The chain is usually the `x5c` of the Credential Issuer metadata or the Request Object.
   */
  wrpacChain: [string, ...string[]];
  /**
   * The WRPAC LoTE to get the trust anchor from
   */
  lote: ParsedLoTE;
  callbacks: {
    getX509CertificateMetadata: GetX509CertificateMetadataCallback;
    verifyX509CertificateChain: VerifyX509CertificateChainCallback;
  };
  now?: Date;
};

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
    await options.callbacks.getX509CertificateMetadata(options.wrpacChain[0]),
    "WRPAC schema validation failed",
  );

  const trustAnchor = await validateLoTECertificateChain({
    ...options,
    chain: options.wrpacChain,
    profile: LoTEProfile.EUWRPACProvidersList,
    serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPAC/Issuance",
  });

  return trustAnchor;
}
