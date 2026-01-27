import type { RequestLike } from "@pagopa/io-wallet-utils";

import { extractClientAttestationJwtsFromHeaders } from "../client-attestation-pop";
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
    clientAttestationJwt: string;
    clientAttestationPopJwt: string;
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
 * Parse an authorization request.
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
    clientAttestation: extractedClientAttestationJwts.clientAttestationHeader
      ? {
          clientAttestationJwt:
            extractedClientAttestationJwts.clientAttestationHeader,
          clientAttestationPopJwt:
            extractedClientAttestationJwts.clientAttestationPopHeader,
        }
      : undefined,
    dpop: extractedDpopJwt.dpopJwt
      ? {
          jwt: extractedDpopJwt.dpopJwt,
        }
      : undefined,
  };
}
