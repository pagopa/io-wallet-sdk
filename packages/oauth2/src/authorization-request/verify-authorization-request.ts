import {
  AuthorizationServerMetadata,
  CallbackContext,
  Jwk,
} from "@openid4vc/oauth2";
import { RequestLike } from "@pagopa/io-wallet-utils";

import {
  ClientAttestationOptions,
  VerifiedClientAttestationJwt,
  VerifiedClientAttestationPopJwt,
  verifyClientAttestation,
} from "../client-attestation";
import { Oauth2Error } from "../errors";
import { verifyTokenDPoP } from "../token-dpop";

export interface VerifyAuthorizationRequestDPoP {
  /**
   * Allowed dpop signing alg values. If not provided
   * any alg values are allowed and it's up to the `verifyJwtCallback`
   * to handle the alg.
   */
  allowedSigningAlgs?: string[];

  /**
   * The dpop jwt from the pushed authorization request.
   * If dpop is required, `jwt` MUST be provided
   */
  jwt?: string;

  /**
   * Whether dpop is required.
   */
  required?: boolean;
}

export interface VerifyAuthorizationRequestResult {
  /**
   * The verified client attestation if any were provided.
   */
  clientAttestation?: {
    clientAttestation: VerifiedClientAttestationJwt;
    clientAttestationPop: VerifiedClientAttestationPopJwt;
  };

  dpop?: {
    /**
     * The JWK will be returned if a DPoP proof was provided in the header.
     */
    jwk?: Jwk;

    /**
     * base64url encoding of the JWK SHA-256 Thumbprint (according to [RFC7638])
     * of the DPoP public key (in JWK format).
     *
     * This will always be returned if dpop is used for the PAR endpoint
     */
    jwkThumbprint: string;
  };
}

export interface VerifyAuthorizationRequestOptions {
  authorizationRequest: {
    client_id?: string;
  };

  authorizationServerMetadata: AuthorizationServerMetadata;
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">;

  clientAttestation: ClientAttestationOptions;
  dpop?: VerifyAuthorizationRequestDPoP;

  /**
   * Date to use for expiration. If not provided current date will be used.
   */
  now?: Date;

  request: RequestLike;
}

/**
 * Verifies an authorization request by validating DPoP and client attestation credentials.
 *
 * This function performs cryptographic verification of DPoP proofs and client attestation
 * JWTs extracted from authorization request headers. It validates signatures, checks
 * expiration times, and optionally ensures that DPoP and client attestation use the same key.
 *
 * **Important:** This function performs verification only. Use `parseAuthorizationRequest`
 * first to extract the necessary JWTs from request headers.
 *
 * @param options - The verification options
 * @param options.authorizationRequest - The authorization request parameters containing client_id
 * @param options.authorizationServerMetadata - Authorization server metadata including issuer
 * @param options.callbacks - Cryptographic callback functions for hash and JWT verification
 * @param options.dpop - Optional DPoP verification configuration
 * @param options.dpop.jwt - The DPoP JWT extracted from request headers
 * @param options.dpop.required - Whether DPoP is required (will throw if missing)
 * @param options.dpop.allowedSigningAlgs - Allowed signing algorithms for DPoP
 * @param options.clientAttestation - Client attestation verification configuration
 * @param options.clientAttestation.clientAttestationJwt - The client attestation JWT from headers
 * @param options.clientAttestation.clientAttestationPopJwt - The client attestation PoP JWT from headers
 * @param options.clientAttestation.ensureConfirmationKeyMatchesDpopKey - Whether to verify DPoP and client attestation use the same key
 * @param options.request - The HTTP request object containing URL and headers
 * @param options.now - Optional date for time-based validation (defaults to current time)
 *
 * @returns A promise resolving to verification results containing:
 * - `dpop` - Verified DPoP information including JWK and thumbprint (if DPoP was provided)
 * - `clientAttestation` - Verified client attestation JWTs (if client attestation was provided)
 *
 * @throws {Oauth2Error} When DPoP is required but missing
 * @throws {Oauth2Error} When client attestation is required but missing
 * @throws {Oauth2Error} When client_id doesn't match between request and client attestation
 * @throws {Oauth2Error} When DPoP and client attestation keys don't match (if ensureConfirmationKeyMatchesDpopKey is true)
 * @throws {Oauth2Error} When JWT signature verification fails
 * @throws {Oauth2Error} When JWT is expired or has invalid claims
 *
 * @example
 * ```typescript
 * const result = await verifyAuthorizationRequest({
 *   authorizationRequest: { client_id: 'client-123' },
 *   authorizationServerMetadata: { issuer: 'https://auth.example.com' },
 *   callbacks: { hash: hashCallback, verifyJwt: verifyJwtCallback },
 *   dpop: {
 *     jwt: dpopJwtFromHeaders,
 *     required: true,
 *     allowedSigningAlgs: ['ES256']
 *   },
 *   clientAttestation: {
 *     clientAttestationJwt: clientAttJwtFromHeaders,
 *     clientAttestationPopJwt: clientAttPopJwtFromHeaders,
 *     required: true,
 *     ensureConfirmationKeyMatchesDpopKey: true
 *   },
 *   request: httpRequest
 * });
 *
 * console.log(result.dpop?.jwkThumbprint);
 * console.log(result.clientAttestation?.clientAttestation.payload.sub);
 * ```
 */
export async function verifyAuthorizationRequest(
  options: VerifyAuthorizationRequestOptions,
): Promise<VerifyAuthorizationRequestResult> {
  const dpopResult = options.dpop
    ? await verifyAuthorizationRequestDpop(
        options.dpop,
        options.request,
        options.callbacks,
        options.now,
      )
    : undefined;

  const clientAttestationResult = await verifyClientAttestation({
    authorizationServerMetadata: options.authorizationServerMetadata,
    callbacks: options.callbacks,
    clientAttestation: options.clientAttestation,
    dpopJwkThumbprint: dpopResult?.jwkThumbprint,
    now: options.now,
    requestClientId: options.authorizationRequest.client_id,
  });

  return {
    clientAttestation: clientAttestationResult,
    dpop: dpopResult?.jwkThumbprint
      ? {
          jwk: dpopResult.jwk,
          jwkThumbprint: dpopResult.jwkThumbprint,
        }
      : undefined,
  };
}

async function verifyAuthorizationRequestDpop(
  options: VerifyAuthorizationRequestDPoP,
  request: RequestLike,
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">,
  now?: Date,
) {
  if (options.required && !options.jwt) {
    throw new Oauth2Error(
      `Missing required DPoP parameters in authorization request. DPoP header is required.`,
    );
  }

  const verifyDpopResult = options.jwt
    ? await verifyTokenDPoP({
        allowedSigningAlgs: options.allowedSigningAlgs,
        callbacks,
        dpopJwt: options.jwt,
        now,
        request,
      })
    : undefined;

  return {
    jwk: verifyDpopResult?.header.jwk,
    jwkThumbprint: verifyDpopResult?.jwkThumbprint,
  };
}
