import type { RequestLike } from "@pagopa/io-wallet-utils";

import { extractClientAttestationJwtsFromHeaders } from "../client-attestation";
import { Oauth2Error } from "../errors";
import { extractDpopJwtFromHeaders } from "../token-dpop";

export interface ParseAuthorizationRequestOptions {
  request: RequestLike;
}

export interface ParseAuthorizationRequestResult {
  /**
   * The client attestation jwts from the authorization request headers.
   * These have not been verified yet.
   */
  clientAttestation?: {
    clientAttestationPopJwt: string;
    walletAttestationJwt: string;
  };

  /**
   * The dpop jwt from the authorization request DPoP header.
   *
   * The signer of the jwt has not been verified yet, this only happens during verification.
   */
  dpop?: {
    jwt: string;
  };
}

/**
 * Parse an authorization request by extracting DPoP and client attestation
 * information from HTTP request headers.
 *
 * **Important:** This function performs extraction and basic format validation
 * but does NOT verify cryptographic signatures. JWT signature verification
 * should be performed separately using the appropriate verification functions.
 *
 * @returns Parsed authorization request result containing:
 * - `dpop` - DPoP information if present (jwt)
 * - `clientAttestation` - Client attestation JWTs if present
 *
 * @throws {Oauth2Error} When DPoP JWT format is invalid
 * @throws {Oauth2Error} When client attestation headers are incomplete
 */
export function parseAuthorizationRequest(
  options: ParseAuthorizationRequestOptions,
): ParseAuthorizationRequestResult {
  // We only parse the dpop, we don't verify it yet
  const extractedDpopJwt = extractDpopJwtFromHeaders(options.request.headers);
  if (!extractedDpopJwt.valid) {
    throw new Oauth2Error(
      "Request contains a 'DPoP' header, but the value is not a valid DPoP jwt",
    );
  }

  // We only parse the client attestations, we don't verify it yet
  const extractedClientAttestationJwts =
    extractClientAttestationJwtsFromHeaders(options.request.headers);
  if (!extractedClientAttestationJwts.valid) {
    throw new Oauth2Error(
      "Request contains client attestation header, but the values are not valid client attestation and client attestation PoP header.",
    );
  }

  return {
    clientAttestation: extractedClientAttestationJwts.walletAttestationHeader
      ? {
          clientAttestationPopJwt:
            extractedClientAttestationJwts.clientAttestationPopHeader,
          walletAttestationJwt:
            extractedClientAttestationJwts.walletAttestationHeader,
        }
      : undefined,
    dpop: extractedDpopJwt.dpopJwt
      ? {
          jwt: extractedDpopJwt.dpopJwt,
        }
      : undefined,
  };
}
