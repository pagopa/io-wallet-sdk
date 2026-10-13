import {
  CallbackContext,
  createFetcher,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { EudiTrustError, LoTEError } from "../errors";
import { MAX_LOTE_PIVOTS } from "./constants";
import { ParsedLoTE, ValidateLoTEOptions, validateLoTE } from "./validate-lote";
import { LoTE } from "./z-lote";

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

export interface FetchAndValidateLoTEOptions extends Omit<
  ValidateLoTEOptions,
  "callbacks" | "jwt"
> {
  callbacks: Pick<CallbackContext, "fetch"> & ValidateLoTEOptions["callbacks"];
  /**
   * The URL to the latest Official Journal of the European Union publication.
   */
  ojeuUrl: string;
  url: string;
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

/**
 * Download the LoTE from `url` and authenticate it with {@link validateLoTE}.
 * The LoTE is assumed to have no pivots.
 */
export async function fetchAndValidateLoTE(
  options: FetchAndValidateLoTEOptions,
): Promise<ParsedLoTE> {
  const loteJwt = await fetchLoTE(options);

  // Current LoTEs do not include the OJEU URL, so the next line is commented out as it requires that URL.
  // const pivotUrls = getLoTEPivotUrls(decodedLote.payload.LoTE, options.ojeuUrl)
  // TODO: add pivot validation.

  return validateLoTE({ ...options, jwt: loteJwt });
}
