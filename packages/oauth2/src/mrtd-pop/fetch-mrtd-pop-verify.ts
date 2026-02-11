import { CallbackContext } from "@openid4vc/oauth2";
import { createFetcher, parseWithErrorHandling } from "@openid4vc/utils";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { MrtdPopError } from "../errors";
import { zMrtdPopVerifyResponse } from "./z-mrtd-pop";

export interface FetchMrtdPopVerifyOptions {
  callbacks: Pick<CallbackContext, "fetch">;
  clientAttestationDPoP: string;
  mrtdAuthSession: string;
  mrtdPopNonce: string;
  mrtdValidationJwt: string;
  popVerifyEndpoint: string;
  walletAttestation: string;
}

export interface FetchMrtdPopVerifyResult {
  mrtdValPopNonce: string;
  redirectUri: string;
}

/**
 * Submits MRTD validation evidence for final verification (Phase 3.4 of L2+ flow).
 *
 * Sends the validation JWT containing NFC-read document data to the MRTD PoP Service.
 * The service performs cryptographic verification, identity correlation, and document status checks.
 *
 * @param options - Validation JWT, session correlation parameters, and attestation headers
 * @returns Final nonce and redirect URI for browser-based confirmation
 * @throws {UnexpectedStatusCodeError} If response is not HTTP 202
 * @throws {ValidationError} If response body is invalid
 * @throws {MrtdPopError} For network failures
 *
 * @see IT-Wallet L2+ specification Section 12.1.3.5.3.4 (MRTD PoP Validation Request)
 */
export async function fetchMrtdPopVerify(
  options: FetchMrtdPopVerifyOptions,
): Promise<FetchMrtdPopVerifyResult> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);

    const response = await fetch(options.popVerifyEndpoint, {
      body: JSON.stringify({
        mrtd_auth_session: options.mrtdAuthSession,
        mrtd_pop_nonce: options.mrtdPopNonce,
        mrtd_validation_jwt: options.mrtdValidationJwt,
      }),
      headers: {
        [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.JSON,
        [HEADERS.OAUTH_CLIENT_ATTESTATION]: options.walletAttestation,
        [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]: options.clientAttestationDPoP,
      },
      method: "POST",
    });

    await hasStatusOrThrow(202, UnexpectedStatusCodeError)(response);

    const parsed = parseWithErrorHandling(
      zMrtdPopVerifyResponse,
      await response.json(),
      "Failed to parse MRTD PoP verify response",
    );

    return {
      mrtdValPopNonce: parsed.mrtd_val_pop_nonce,
      redirectUri: parsed.redirect_uri,
    };
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new MrtdPopError(
      `Unexpected error during MRTD PoP verify: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
