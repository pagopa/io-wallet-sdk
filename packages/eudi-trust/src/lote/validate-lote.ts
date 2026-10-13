import {
  CallbackContext,
  decodeBase64,
  decodeJwt,
  encodeToBase64Url,
  verifyJwt,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { LoTEError } from "../errors";
import { LoTEProfile } from "./constants";
import { LoTE, LoTEDocument, LoTEJwtHeader, zLoTEJwtHeader } from "./z-lote";
import {
  zEAAProvidersList,
  zMDLProvidersList,
  zPIDProvidersList,
  zPubEAAProvidersList,
  zWRPACProvidersList,
  zWRPRCProvidersList,
  zWalletProvidersList,
} from "./z-profiles";

export interface X509CertificateMetadata {
  /** Country code (C) of the Subject Distinguished Name. */
  country?: string;
  /** End of the validity period, checked when provided. */
  notAfter?: Date;
  /** Start of the validity period, checked when provided. */
  notBefore?: Date;
  /** Organization (O) values of the Subject Distinguished Name. */
  organizations: string[];
}

/** Parse a DER certificate encoded in base64, as found in the `x5c` header. */
export type GetX509CertificateMetadataCallback = (
  certificate: string,
) => Promise<X509CertificateMetadata> | X509CertificateMetadata;

export interface ValidateLoTEOptions {
  callbacks: {
    getX509CertificateMetadata: GetX509CertificateMetadataCallback;
  } & Pick<CallbackContext, "hash" | "verifyJwt">;
  jwt: string;
  now?: Date;
  profile: LoTEProfile;
  /**
   * `OJEU-LoTE-Certs-Set`: DER certificates encoded in base64, trusted through
   * the Official Journal of the European Union publication.
   */
  trustedCertificates: string[];
}

export interface ParsedLoTE {
  compact: string;
  document: LoTE;
  header: LoTEJwtHeader;
}

const profilesConfig: Record<LoTEProfile, z.ZodType<LoTEDocument>> = {
  [LoTEProfile.EUEAAProvidersList]: zEAAProvidersList,
  [LoTEProfile.EUPIDProvidersList]: zPIDProvidersList,
  [LoTEProfile.EUPubEAAProvidersList]: zPubEAAProvidersList,
  [LoTEProfile.EUWRPACProvidersList]: zWRPACProvidersList,
  [LoTEProfile.EUWRPRCProvidersList]: zWRPRCProvidersList,
  [LoTEProfile.EUWalletProvidersList]: zWalletProvidersList,
  [LoTEProfile.mDLProvidersList]: zMDLProvidersList,
};

/**
 * Digital Signature Validation (step 6 of the IT-Wallet LoTE validation algorithm,
 * PRO-4.1.4-07/08 of ETSI TS 119 615): validate the compact JAdES B-B signature
 * using `LoTE-Signer-Cert` as a directly trusted certificate, and match its
 * subject C and O against the scheme territory and operator name
 * (ETSI TS 119 602 clause 6.8.0). The certificate validity period, when
 * provided, is checked at the validation time.
 */
async function verifyLoTESignature(
  lote: ParsedLoTE,
  payload: LoTEDocument,
  callbacks: ValidateLoTEOptions["callbacks"],
  now: Date,
): Promise<void> {
  const { header } = lote;
  const [signerCertificate] = header.x5c;
  const info = lote.document.ListAndSchemeInformation;

  // ETSI TS 119 182-1: x5t#o is the digest of the signing certificate.
  const x5tO = header["x5t#o"];
  if (x5tO) {
    const digest = await callbacks.hash(
      decodeBase64(signerCertificate),
      x5tO.digAlg,
    );
    if (encodeToBase64Url(digest) !== x5tO.digVal) {
      throw new LoTEError("x5t#o does not match the LoTE signer certificate", {
        code: "LoTE_SIGNATURE_VERIFICATION_FAILED",
      });
    }
  }

  const metadata =
    await callbacks.getX509CertificateMetadata(signerCertificate);
  if (
    metadata.country !== info.SchemeTerritory ||
    !metadata.organizations.some((organization) =>
      info.SchemeOperatorName.some(({ value }) => value === organization),
    )
  ) {
    throw new LoTEError(
      "LoTE signer certificate subject does not match the scheme territory and operator name",
      {
        code: "LoTE_SIGNATURE_VERIFICATION_FAILED",
      },
    );
  }

  if (
    (metadata.notBefore && now < metadata.notBefore) ||
    (metadata.notAfter && now > metadata.notAfter)
  ) {
    throw new LoTEError("LoTE signer certificate is not valid at this time", {
      code: "LoTE_SIGNATURE_VERIFICATION_FAILED",
    });
  }

  try {
    await verifyJwt({
      compact: lote.compact,
      header,
      payload,
      signer: { alg: header.alg, method: "x5c", x5c: [signerCertificate] },
      skipTimeBasedValidation: true,
      verifyJwtCallback: callbacks.verifyJwt,
    });
  } catch (error) {
    throw new LoTEError("Invalid LoTE signature", {
      cause: error,
      code: "LoTE_SIGNATURE_VERIFICATION_FAILED",
    });
  }
}

/**
 * Authenticate a List of Trusted Entities without pivots, following the
 * IT-Wallet "List of Trusted Entities Validation" algorithm, which applies
 * ETSI TS 119 615 clause 4.1 to ETSI TS 119 602 lists:
 * - step 2: `LoTE-Signer-Cert` is the first `x5c` certificate;
 * - step 6: JAdES signature validation;
 * - step 8: `LoTE-Signer-Cert` must belong to `OJEU-LoTE-Certs-Set`;
 * - step 9: the list must not be past its `NextUpdate`.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#eudiw-trust-anchor-validation
 * @see https://www.etsi.org/deliver/etsi_TS/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 */
export async function validateLoTE(
  options: ValidateLoTEOptions,
): Promise<ParsedLoTE> {
  const { compact, header, payload } = decodeJwt({
    headerSchema: zLoTEJwtHeader,
    jwt: options.jwt,
    payloadSchema: profilesConfig[options.profile],
  });
  const lote: ParsedLoTE = { compact, document: payload.LoTE, header };

  const now = options.now ?? new Date();
  await verifyLoTESignature(lote, payload, options.callbacks, now);

  if (!options.trustedCertificates.includes(header.x5c[0])) {
    throw new LoTEError("LoTE signer certificate is not trusted by the OJEU", {
      code: "PIVOT_n_SIGNER_CERT_NOT_AUTHENTICATED_BY_OJEU",
    });
  }

  if (now >= new Date(lote.document.ListAndSchemeInformation.NextUpdate)) {
    throw new LoTEError("LoTE has expired", { code: "LoTE_EXPIRED" });
  }

  return lote;
}
