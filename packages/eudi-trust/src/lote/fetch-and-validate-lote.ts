import {
  CallbackContext,
  createFetcher,
  decodeJwt,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { LoTEError } from "../errors";
import { verifyJAdESSignature } from "../jades/verify-jades-signature";
import { includesCertificate } from "../x509/certificate";
import { GetX509CertificateMetadataCallback } from "../x509/types";
import { LoTEProfile, MAX_LOTE_PIVOTS } from "./constants";
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

export interface FetchLoTEOptions {
  callbacks: Pick<CallbackContext, "fetch">;
  /** The URL to download the LoTE from. */
  loteUrl: string;
}

export interface ValidateLoTEOptions {
  callbacks: {
    getX509CertificateMetadata: GetX509CertificateMetadataCallback;
  } & Pick<CallbackContext, "hash" | "verifyJwt">;
  /** The compact JAdES signed LoTE. */
  loteJwt: string;
  /** Validation time. Defaults to the current time. */
  now?: Date;
  /** The expected LoTE profile, which selects the schema the LoTE must follow. */
  profile: LoTEProfile;
  /**
   * DER certificates encoded in base64, trusted through
   * the Official Journal of the European Union publication.
   */
  trustedCertificates: string[];
}

export interface FetchAndValidateLoTEOptions
  extends
    Omit<FetchLoTEOptions, "callbacks">,
    Omit<ValidateLoTEOptions, "callbacks" | "loteJwt"> {
  callbacks: FetchLoTEOptions["callbacks"] & ValidateLoTEOptions["callbacks"];
  /**
   * The URL to the latest Official Journal of the European Union publication.
   * Not used yet: LoTE pivots are not supported.
   */
  ojeuUrl?: string;
}

export interface ParsedLoTE {
  compact: string;
  document: LoTE;
  header: LoTEJwtHeader;
}

const ALLOWED_LOTE_CONTENT_TYPES = [
  "application/jose",
  "application/jwt",
  "application/json",
];

/**
 * Downloads a signed LoTE without validating it: use {@link validateLoTE} or
 * {@link fetchAndValidateLoTE} before trusting its content.
 *
 * @returns The compact signed LoTE.
 * @throws {LoTEError} if the response is not a signed LoTE.
 */
export async function fetchLoTE(options: FetchLoTEOptions): Promise<string> {
  const fetch = createFetcher(options.callbacks.fetch);

  const response = await fetch(options.loteUrl, {
    headers: { Accept: "application/jose, application/jwt" },
  });

  const contentType = response.headers.get("Content-Type");
  if (
    !ALLOWED_LOTE_CONTENT_TYPES.some((allowedContentType) =>
      contentType?.includes(allowedContentType),
    )
  ) {
    throw new LoTEError(
      `Unsupported content type ${contentType}: expected one of ${ALLOWED_LOTE_CONTENT_TYPES.join(", ")}`,
      { code: "LoTE_FETCH_FAILED" },
    );
  }

  await hasStatusOrThrow(200)(response);
  return (await response.text()).trim();
}

/**
 * Verifies the signature of the LoTE. Its signer certificate is not chained to
 * a Trust Anchor: it is authenticated afterwards against the OJEU certificates.
 */
async function verifyLoTESignature(
  lote: ParsedLoTE,
  payload: LoTEDocument,
  callbacks: ValidateLoTEOptions["callbacks"],
  now: Date,
): Promise<void> {
  const { header } = lote;
  // const info = lote.document.ListAndSchemeInformation;

  const metadata = await callbacks.getX509CertificateMetadata(header.x5c[0]);

  // ETSI SPEC-DEVIATION
  // ETSI TS 119 602 section 6.8.0 on digital signature states that the certificate's country code
  // and organization must match the scheme territory and one of the scheme operator name values in the LoTE.
  // EUDIW Launchpad LoTEs countries and scheme operatore name do not match, so the following checks are commented out.
  /* if (metadata.country !== info.SchemeTerritory) {
    throw new LoTEError(
      `LoTE signer certificate subject's country does not match the scheme territory. Expected ${info.SchemeTerritory}, found ${metadata.country}`,
      { code: "LoTE_SIGNATURE_VERIFICATION_FAILED" },
    );
  }
  if (
    !metadata.organizations.some((organization) =>
      info.SchemeOperatorName.some(({ value }) => value === organization),
    )
  ) {
    throw new LoTEError(
      `LoTE signer certificate subject's organization does not match any scheme operator name. Found ${metadata.organizations.join(", ")}`,
      { code: "LoTE_SIGNATURE_VERIFICATION_FAILED" },
    );
  } */

  if (
    (metadata.notBefore && now < metadata.notBefore) ||
    (metadata.notAfter && now > metadata.notAfter)
  ) {
    throw new LoTEError("LoTE signer certificate is not valid at this time", {
      code: "LoTE_SIGNATURE_VERIFICATION_FAILED",
    });
  }

  await verifyJAdESSignature({
    callbacks,
    compact: lote.compact,
    header,
    payload,
    errorMessagePrefix: "LoTE signature verification failed:",
  });
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
 * Authenticates a List of Trusted Entities (ETSI TS 119 602), as per the
 * IT-Wallet LoTE validation algorithm based on ETSI TS 119 615. Pivots are not
 * supported: the signer must be one of `trustedCertificates`.
 *
 * A validated LoTE can be reused until its `NextUpdate`.
 *
 * @returns The decoded LoTE.
 * @throws {ValidationError} if the LoTE is malformed.
 * @throws {JAdESError} if the signature is invalid.
 * @throws {LoTEError} if the LoTE cannot be trusted, or is expired.
 *
 * @see https://italia.github.io/eid-wallet-it-docs/1.5.0/en/trust-evaluation.html#eudiw-trust-anchor-validation
 * @see https://www.etsi.org/deliver/etsi_TS/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf
 */
export async function validateLoTE(
  options: ValidateLoTEOptions,
): Promise<ParsedLoTE> {
  const { compact, header, payload } = decodeJwt({
    headerSchema: zLoTEJwtHeader,
    jwt: options.loteJwt,
    payloadSchema: profilesConfig[options.profile],
  });
  const lote: ParsedLoTE = { compact, document: payload.LoTE, header };

  const now = options.now ?? new Date();

  if (
    now < new Date(lote.document.ListAndSchemeInformation.ListIssueDateTime)
  ) {
    throw new LoTEError("LoTE is not yet valid", {
      code: "LoTE_NOT_YET_VALID",
    });
  }
  if (now >= new Date(lote.document.ListAndSchemeInformation.NextUpdate)) {
    throw new LoTEError("LoTE has expired", { code: "LoTE_EXPIRED" });
  }

  await verifyLoTESignature(lote, payload, options.callbacks, now);

  if (!includesCertificate(options.trustedCertificates, lote.header.x5c[0])) {
    throw new LoTEError("LoTE signer certificate is not trusted by the OJEU", {
      code: "PIVOT_n_SIGNER_CERT_NOT_AUTHENTICATED_BY_OJEU",
    });
  }

  return lote;
}

/**
 * Returns the locations of the pivot LoTEs, from newest to oldest. Not used yet
 * by `fetchAndValidateLoTE`.
 *
 * @returns The pivot URLs.
 * @throws {LoTEError} if the pivots cannot be discovered safely.
 */
export function getLoTEPivotUrls(lote: LoTE, ojeuUrl: string): string[] {
  const uris = (lote.ListAndSchemeInformation.SchemeInformationURI ?? []).map(
    ({ uriValue }) => uriValue,
  );

  const ojeuUrlIndex = uris.indexOf(ojeuUrl);
  if (ojeuUrlIndex < 0) {
    throw new LoTEError("OJEU publication is missing from scheme information", {
      code: "OJEU_LOCATION_INPUT_NOT_MATCHING_OJEU_LOCATION_IN_LoTE",
    });
  }

  const pivotUrls = uris.slice(0, ojeuUrlIndex);
  if (pivotUrls.length > MAX_LOTE_PIVOTS) {
    throw new LoTEError("LoTE pivot safety limit exceeded", {
      code: "LoTE_TRAVERSAL_LIMIT",
    });
  }

  return pivotUrls;
}

/**
 * Downloads a LoTE and authenticates it with {@link validateLoTE}, which
 * defines the errors thrown. The LoTE is assumed to have no pivots.
 *
 * @returns The validated and decoded LoTE.
 * @throws {LoTEError}
 */
export async function fetchAndValidateLoTE(
  options: FetchAndValidateLoTEOptions,
): Promise<ParsedLoTE> {
  const loteJwt = await fetchLoTE(options);

  // Current LoTEs do not include the OJEU URL, so the next line is commented out as it requires that URL.
  // const pivotUrls = getLoTEPivotUrls(decodedLote.payload.LoTE, options.ojeuUrl)
  // TODO: add pivot validation.

  return validateLoTE({ ...options, loteJwt });
}
