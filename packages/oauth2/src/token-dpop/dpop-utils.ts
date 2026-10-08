import { HEADERS } from "@pagopa/io-wallet-utils";

import { zDpopNonceErrorResponse } from "./z-dpop";

/**
 * Normalizes a request URL into the DPoP `htu` claim value.
 *
 * @param requestUrl - Full request URL.
 * @returns URL string without query string or fragment.
 */
export const htuFromRequestUrl = (requestUrl: string) => {
  const htu = new URL(requestUrl);
  htu.search = "";
  htu.hash = "";

  return htu.toString();
};

/**
 * A DPoP proof, either already created or created on demand.
 *
 * When a factory is provided, the request is retried once with the nonce the server
 * returns in the `DPoP-Nonce` header together with a `use_dpop_nonce` error (RFC 9449, Sections 8 and 9).
 */
export type DpopProof = ((nonce?: string) => Promise<string>) | string;

/**
 * Options for sending a DPoP-protected request
 */
export interface FetchWithDpopNonceRetryOptions {
  /**
   * The DPoP proof, or its factory to enable the retry with the server nonce
   */
  dPoP: DpopProof;

  /**
   * Sends the request with the given DPoP proof
   */
  sendRequest: (dPoP: string) => Promise<Response>;
}

/**
 * Checks whether the server rejected the request because a DPoP nonce is required:
 * authorization servers return a `use_dpop_nonce` error in the body (RFC 9449, Section 8),
 * resource servers in the `WWW-Authenticate` header (RFC 9449, Section 9).
 *
 * @param response - The server response.
 * @returns The nonce to use, or `undefined` when no nonce is required.
 */
export async function getRequiredDpopNonce(
  response: Response,
): Promise<string | undefined> {
  if (response.status !== 400 && response.status !== 401) return undefined;

  const nonce = response.headers.get(HEADERS.DPOP_NONCE);
  if (!nonce) return undefined;

  if (response.status === 401) {
    const wwwAuthenticate = response.headers.get(HEADERS.WWW_AUTHENTICATE);
    return wwwAuthenticate?.includes("use_dpop_nonce") ? nonce : undefined;
  }

  const body = await response
    .clone()
    .json()
    .catch(() => undefined);
  return zDpopNonceErrorResponse.safeParse(body).success ? nonce : undefined;
}

/**
 * Sends a DPoP-protected request and, when the proof is a factory, retries it once
 * with the nonce required by the server.
 *
 * @param options - {@link FetchWithDpopNonceRetryOptions}
 * @returns The server response.
 */
export async function fetchWithDpopNonceRetry(
  options: FetchWithDpopNonceRetryOptions,
): Promise<Response> {
  if (typeof options.dPoP === "string") {
    return options.sendRequest(options.dPoP);
  }

  const response = await options.sendRequest(await options.dPoP());
  const nonce = await getRequiredDpopNonce(response);
  return nonce ? options.sendRequest(await options.dPoP(nonce)) : response;
}
