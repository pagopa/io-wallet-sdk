import {
  CallbackContext,
  createFetcher,
  decodeJwt,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";
import z from "zod";

import { EudiTrustError, LoTEError } from "../errors";
import { LoTEProfile, MAX_LOTE_PIVOTS } from "./constants";
import {
  LoTE,
  LoTEDocument,
  LoTEJwtHeader,
  zLoTEJwtHeader,
} from "./z-lote";
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
  url: string;
}

export async function fetchLoTE(options: FetchLoTEOptions): Promise<string> {
  const fetch = createFetcher(options.callbacks.fetch);

  const response = await fetch(options.url, {
    headers: { Accept: "application/jose, application/jwt" },
  });

  const contentType = response.headers.get("Content-Type");
  if (
    !contentType?.includes("application/jose") &&
    !contentType?.includes("application/jwt")
  ) {
    throw new EudiTrustError(
      `Unsupported content type ${contentType}: expected jose or jwt`,
    );
  }

  await hasStatusOrThrow(200)(response);
  return (await response.text()).trim();
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

interface FetchAndValidateLoTEOptions {
  callbacks: Pick<CallbackContext, "fetch">;
  /**
   * The URL to the latest Official Journal of the European Union publication.
   */
  ojeuUrl: string;
  profile: LoTEProfile;
  url: string;
}

export interface ParsedLoTE {
  compact: string;
  document: LoTE;
  header: LoTEJwtHeader;
}

/**
 * Discover historical list locations (pivots), ordered newest to oldest.
 * Before all pivots, the URL of the Official Journal of the European Union publication is expected.
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

export async function fetchAndValidateLoTE(
  options: FetchAndValidateLoTEOptions,
): Promise<ParsedLoTE> {
  const loteJwt = await fetchLoTE(options);

  const payloadSchema = profilesConfig[options.profile];

  const decodedLote = decodeJwt({
    headerSchema: zLoTEJwtHeader,
    jwt: loteJwt,
    payloadSchema,
  });

  // Current LoTEs do not include the OJEU URL, so the next line is commented out as it requires that URL.
  // const pivotUrls = getLoTEPivotUrls(decodedLote.payload.LoTE, options.ojeuUrl)
  // TODO: add pivot validation.

  return {
    compact: decodedLote.compact,
    document: decodedLote.payload.LoTE,
    header: decodedLote.header,
  };
}
