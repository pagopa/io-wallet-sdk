import {
  AuthorizationServerMetadata,
  CallbackContext,
  HashAlgorithm,
  Jwk,
  Oauth2Error,
  calculateJwkThumbprint,
} from "@openid4vc/oauth2";
import { RequestLike } from "@pagopa/io-wallet-utils";

import {
  VerifiedClientAttestationJwt,
  VerifiedClientAttestationPopJwt,
  oauthClientAttestationHeader,
  oauthClientAttestationPopHeader,
  verifyClientAttestationJwt,
  verifyClientAttestationPopJwt,
} from "../client-attestation";
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

export interface VerifyAuthorizationRequestClientAttestation {
  clientAttestationJwt: string;

  clientAttestationPopJwt: string;

  /**
   * Whether to ensure that the key used in client attestation confirmation
   * is the same key used for DPoP. This only has effect if both DPoP and client
   * attestations are present.
   *
   * @default false
   */
  ensureConfirmationKeyMatchesDpopKey?: boolean;
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

  clientAttestation: VerifyAuthorizationRequestClientAttestation;
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

  const clientAttestationResult =
    await verifyAuthorizationRequestClientAttestation(
      options.clientAttestation,
      options.authorizationServerMetadata,
      options.callbacks,
      dpopResult?.jwkThumbprint,
      options.now,
      options.authorizationRequest.client_id,
    );

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

async function verifyAuthorizationRequestClientAttestation(
  options: VerifyAuthorizationRequestClientAttestation,
  authorizationServerMetadata: AuthorizationServerMetadata,
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">,
  dpopJwkThumbprint?: string,
  now?: Date,
  requestClientId?: string,
) {
  if (!options.clientAttestationJwt || !options.clientAttestationPopJwt) {
    throw new Oauth2Error(
      `Missing required client attestation parameters in pushed authorization request. Make sure to provide the '${oauthClientAttestationHeader}' and '${oauthClientAttestationPopHeader}' header values.`,
    );
  }

  const clientAttestation = await verifyClientAttestationJwt({
    callbacks,
    clientAttestationJwt: options.clientAttestationJwt,
    now,
  });

  const clientAttestationPop = await verifyClientAttestationPopJwt({
    authorizationServer: authorizationServerMetadata.issuer,
    callbacks: callbacks,
    clientAttestationPopJwt: options.clientAttestationPopJwt,
    clientAttestationPublicJwk: clientAttestation.payload.cnf.jwk,
    now,
  });

  if (requestClientId && requestClientId !== clientAttestation.payload.sub) {
    // Ensure the client id matches with the client id provided in the authorization request
    throw new Oauth2Error(
      `The client_id '${requestClientId}' in the request does not match the client id '${clientAttestation.payload.sub}' in the client attestation`,
    );
  }

  if (options.ensureConfirmationKeyMatchesDpopKey && dpopJwkThumbprint) {
    const clientAttestationJkt = await calculateJwkThumbprint({
      hashAlgorithm: HashAlgorithm.Sha256,
      hashCallback: callbacks.hash,
      jwk: clientAttestation.payload.cnf.jwk,
    });

    if (clientAttestationJkt !== dpopJwkThumbprint) {
      throw new Oauth2Error(
        "Expected the DPoP JWK thumbprint value to match the JWK thumbprint of the client attestation confirmation JWK. Ensure both DPoP and client attestation use the same key.",
      );
    }
  }

  return {
    clientAttestation,
    clientAttestationPop,
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
