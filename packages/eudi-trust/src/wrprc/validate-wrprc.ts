import { CallbackContext, decodeJwt } from "@pagopa/io-wallet-utils";

import { LoTEProfile } from "../lote/constants";
import {
  WRPRCJwtHeader,
  WRPRCPayload,
  zWRPRCJwtHeader,
  zWRPRCPayload,
} from "./z-wrprc";
import { verifyJAdESSignature } from "../jades";
import {
  GetX509CertificateMetadataCallback,
  validateLoTECertificateChain,
  VerifyX509CertificateChainCallback,
} from "../x509";
import { ParsedLoTE } from "../lote";

export interface ValidateWRPRCOptions {
  callbacks: {
    hash: CallbackContext["hash"];
    verifyJwt: CallbackContext["verifyJwt"];
    getX509CertificateMetadata: GetX509CertificateMetadataCallback;
    verifyX509CertificateChain: VerifyX509CertificateChainCallback;
  };
  /** The WRPRC JWT to validate */
  wrprcJwt: string;
  /** A LoTE authenticated with `validateLoTE`. */
  lote: ParsedLoTE;
  now?: Date;
}

export interface ValidatedWRPRC {
  compact: string;
  header: WRPRCJwtHeader;
  payload: WRPRCPayload;
  /** The Trust Anchor that validated the WRPRC signing certificate chain. */
  trustAnchor: string;
}

/**
 * IT-Wallet "Wallet-Relying Party Registration Certificate Validation", steps 1
 * and 3-6, for the JWT form (ETSI TS 119 475 clause 5.2.1):
 * 1. `typ` is `rc-wrp+jwt`, and header and payload follow ETSI TS 119 475
 *    clause 5.2 (see `zWRPRCJwtHeader` and `zWRPRCPayload`);
 * 3. the JAdES B-B signature is valid for the first `x5c` certificate (`x5t#o`
 *    included);
 * 4-5. the `x5c` chain is validated against the Trust Anchors of the
 *    `WRPRC/Issuance` service of a Providers of WRPRC LoTE;
 * 6. `iat`, and `exp` when present, are valid at `now`.
 *
 * The algorithm (step 2), status (step 7) and consistency with the interaction
 * (step 8) are not checked.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#authorization-artifacts-validation
 */
export async function validateWRPRC(
  options: ValidateWRPRCOptions,
): Promise<ValidatedWRPRC> {
  const { compact, header, payload } = decodeJwt({
    errorMessagePrefix: "Error decoding WRPRC:",
    headerSchema: zWRPRCJwtHeader,
    jwt: options.wrprcJwt,
    payloadSchema: zWRPRCPayload,
  });

  await verifyJAdESSignature({
    callbacks: {
      hash: options.callbacks.hash,
      verifyJwt: options.callbacks.verifyJwt,
    },
    compact,
    header: header,
    now: options.now,
    payload,
  });

  const trustAnchor = await validateLoTECertificateChain({
    callbacks: options.callbacks,
    chain: header.x5c,
    lote: options.lote,
    profile: LoTEProfile.EUWRPRCProvidersList,
    serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance",
  });

  return { compact, header, payload, trustAnchor };
}
