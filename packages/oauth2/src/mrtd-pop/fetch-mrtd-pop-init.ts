import { CallbackContext, JwtSignerJwk, decodeJwt } from "@openid4vc/oauth2";
import { createFetcher } from "@openid4vc/utils";
import {
  CONTENT_TYPES,
  HEADERS,
  UnexpectedStatusCodeError,
  ValidationError,
  hasStatusOrThrow,
} from "@pagopa/io-wallet-utils";

import { MrtdPopError } from "../errors";
import {
  zMrtdPopInitResponseJwtHeader,
  zMrtdPopInitResponseJwtPayload,
} from "./z-mrtd-pop";

export interface FetchMrtdPopInitOptions {
  callbacks: Pick<CallbackContext, "fetch" | "verifyJwt">;
  clientAttestationDPoP: string;
  /** From challenge JWT payload */
  mrtdAuthSession: string;
  /** From challenge JWT payload */
  mrtdPopJwtNonce: string;
  /** From challenge JWT payload htu */
  popInitEndpoint: string;
  signer: JwtSignerJwk;

  walletAttestation: string;
}

export interface FetchMrtdPopInitResult {
  challenge: string;
  mrtdPopNonce: string;
  mrz?: string;
  /** htu from the init response — the verify endpoint */
  popVerifyEndpoint: string;
}

/**
 * Initiates MRTD Proof of Possession validation (Phase 3.2 of L2+ flow).
 *
 * Sends session correlation parameters to the MRTD PoP Service and receives:
 * - Cryptographic challenge for Anti-Cloning Internal Authentication
 * - Nonce for next step
 * - Optional MRZ data from CIE National Registry
 *
 * @param options - Session parameters, attestation headers, and callbacks
 * @returns Challenge, nonce, optional MRZ, and verify endpoint URL
 * @throws {UnexpectedStatusCodeError} If response is not HTTP 202
 * @throws {MrtdPopError} For network or parsing failures
 *
 * It is alligned to the IT-Wallet v1.3 specs
 * @see IT-Wallet L2+ specification Section 12.1.3.5.3.2-3 (MRTD PoP Request/Response)
 */
export async function fetchMrtdPopInit(
  options: FetchMrtdPopInitOptions,
): Promise<FetchMrtdPopInitResult> {
  try {
    const fetch = createFetcher(options.callbacks.fetch);

    const response = await fetch(options.popInitEndpoint, {
      body: JSON.stringify({
        mrtd_auth_session: options.mrtdAuthSession,
        mrtd_pop_jwt_nonce: options.mrtdPopJwtNonce,
      }),
      headers: {
        [HEADERS.CONTENT_TYPE]: CONTENT_TYPES.JSON,
        [HEADERS.OAUTH_CLIENT_ATTESTATION]: options.walletAttestation,
        [HEADERS.OAUTH_CLIENT_ATTESTATION_POP]: options.clientAttestationDPoP,
      },
      method: "POST",
    });

    await hasStatusOrThrow(202, UnexpectedStatusCodeError)(response);

    const responseJwt = await response.text();

    const jwt = decodeJwt({
      headerSchema: zMrtdPopInitResponseJwtHeader,
      jwt: responseJwt,
      payloadSchema: zMrtdPopInitResponseJwtPayload,
    });

    await options.callbacks.verifyJwt(options.signer, {
      compact: responseJwt,
      header: jwt.header,
      payload: jwt.payload,
    });

    return {
      challenge: jwt.payload.challenge,
      mrtdPopNonce: jwt.payload.mrtd_pop_nonce,
      mrz: jwt.payload.mrz,
      popVerifyEndpoint: jwt.payload.htu,
    };
  } catch (error) {
    if (
      error instanceof UnexpectedStatusCodeError ||
      error instanceof ValidationError
    ) {
      throw error;
    }
    throw new MrtdPopError(
      `Unexpected error during MRTD PoP init: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
