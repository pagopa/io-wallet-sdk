import { CallbackContext, decodeJwt } from "@pagopa/io-wallet-utils";

import { verifyJAdESSignature } from "../jades";
import { ParsedLoTE } from "../lote";
import { LoTEProfile } from "../lote/constants";
import {
  GetX509CertificateMetadataCallback,
  VerifyX509CertificateChainCallback,
  validateCertificateChainAgainstLoTE,
} from "../x509";
import {
  WRPRCJwtHeader,
  WRPRCPayload,
  zWRPRCJwtHeader,
  zWRPRCPayload,
} from "./z-wrprc";

export interface ValidateWRPRCOptions {
  callbacks: {
    getX509CertificateMetadata: GetX509CertificateMetadataCallback;
    hash: CallbackContext["hash"];
    verifyJwt: CallbackContext["verifyJwt"];
    verifyX509CertificateChain: VerifyX509CertificateChainCallback;
  };
  /** Validation time. Defaults to the current time. */
  now?: Date;
  /** The compact WRPRC JWT to validate. */
  wrprcJwt: string;
  /** A Provider of WRPRC LoTE, authenticated with `validateLoTE`. */
  wrprcLote: ParsedLoTE;
}

export interface ValidatedWRPRC {
  compact: string;
  header: WRPRCJwtHeader;
  /** The Trust Anchor that validated the WRPRC signing certificate chain. */
  trustAnchor: string;
  /** The validated and parsed WRPRC payload. */
  wrprc: WRPRCPayload;
}

/**
 * Validates a Wallet-Relying Party Registration Certificate in its JWT form, as
 * per the IT-Wallet authorization artifacts validation based on ETSI TS 119 475.
 *
 * Neither the status of the WRPRC nor its consistency with the interaction in
 * which it is presented are checked.
 *
 * @returns The decoded WRPRC and the Trust Anchor that validated its chain.
 * @throws {ValidationError} if the WRPRC is malformed.
 * @throws {JAdESError} if the signature is invalid or the WRPRC is not valid at `now`.
 * @throws {LoTEError} if `wrprcLote` is not a Provider of WRPRC LoTE.
 * @throws {CertificateChainError} if no Trust Anchor validates the chain.
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

  const trustAnchor = await validateCertificateChainAgainstLoTE({
    callbacks: options.callbacks,
    chain: header.x5c,
    lote: options.wrprcLote,
    now: options.now,
    profile: LoTEProfile.EUWRPRCProvidersList,
    serviceTypeIdentifier: "http://uri.etsi.org/19602/SvcType/WRPRC/Issuance",
  });

  return { compact, header, trustAnchor, wrprc: payload };
}
