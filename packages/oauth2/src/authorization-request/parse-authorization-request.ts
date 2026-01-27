import type { RequestLike } from "@pagopa/io-wallet-utils";

import { extractClientAttestationJwtsFromHeaders } from "../client-attestation-pop";
import { Oauth2Error } from "../errors";
import { extractDpopJwtFromHeaders } from "../token-dpop";

export interface ParseAuthorizationRequestOptions {
  authorizationRequest: {
    dpop_jkt?: string;
  };

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
   * The dpop params from the authorization request.
   *
   * Both `dpop_jkt` and DPoP header can be included in the request.
   *
   * The jkt and the signer of the jwt have not been verified against
   * each other yet, this only happens during verification
   */
  dpop?:
    | {
        jwkThumbprint: string;
        jwt?: string;
      }
    | {
        jwkThumbprint?: string;
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
          jwkThumbprint: options.authorizationRequest.dpop_jkt,
          jwt: extractedDpopJwt.dpopJwt,
        }
      : // Basically the same as above, but with correct TS type hinting
        options.authorizationRequest.dpop_jkt
        ? {
            jwkThumbprint: options.authorizationRequest.dpop_jkt,
            jwt: extractedDpopJwt.dpopJwt,
          }
        : undefined,
  };
}
