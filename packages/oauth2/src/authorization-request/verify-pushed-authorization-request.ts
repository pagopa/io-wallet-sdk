import { JwtSigner } from "@openid4vc/oauth2";

import { VerifiedJarRequest, verifyJarRequest } from "../jar";
import {
  type VerifyAuthorizationRequestOptions,
  type VerifyAuthorizationRequestResult,
  verifyAuthorizationRequest,
} from "./verify-authorization-request";

export interface VerifyPushedAuthorizationRequestReturn
  extends VerifyAuthorizationRequestResult {
  /**
   * The verified JAR request, if `authorizationRequestJwt` was provided
   */
  jar?: VerifiedJarRequest;
}

export interface VerifyPushedAuthorizationRequestOptions
  extends VerifyAuthorizationRequestOptions {
  /**
   * The authorization request JWT to verify. If this value was returned from `parsePushedAuthorizationRequest`
   * you MUST provide this value to ensure the JWT is verified.
   */
  authorizationRequestJwt?: {
    jwt: string;
    signer: JwtSigner;
  };
}

/**
 * Verifies a pushed authorization request (PAR) including JAR, DPoP, and client attestation.
 *
 * This function extends `verifyAuthorizationRequest` by adding support for JWT-secured
 * Authorization Requests (JAR). It performs comprehensive verification of all security
 * mechanisms used in pushed authorization requests according to RFC 9126 (PAR) and
 * RFC 9101 (JAR).
 *
 * The verification process includes:
 * 1. JAR request object verification (if provided) - validates JWT signature and claims
 * 2. DPoP proof verification (if provided) - validates proof of possession
 * 3. Client attestation verification (if provided) - validates client identity
 *
 * **Important:** Use `parsePushedAuthorizationRequest` first to extract the necessary
 * JWTs from request headers and body.
 *
 * @param options - The verification options
 * @param options.authorizationRequest - The authorization request parameters containing client_id
 * @param options.authorizationServerMetadata - Authorization server metadata including issuer
 * @param options.callbacks - Cryptographic callback functions for hash and JWT verification
 * @param options.authorizationRequestJwt - Optional JAR JWT and signer information
 * @param options.authorizationRequestJwt.jwt - The JAR JWT string from request parameter
 * @param options.authorizationRequestJwt.signer - The JWT signer for verification (from federation metadata)
 * @param options.dpop - Optional DPoP verification configuration
 * @param options.dpop.jwt - The DPoP JWT extracted from request headers
 * @param options.dpop.required - Whether DPoP is required (will throw if missing)
 * @param options.dpop.allowedSigningAlgs - Allowed signing algorithms for DPoP
 * @param options.clientAttestation - Optional client attestation verification configuration
 * @param options.clientAttestation.clientAttestationJwt - The client attestation JWT from headers
 * @param options.clientAttestation.clientAttestationPopJwt - The client attestation PoP JWT from headers
 * @param options.clientAttestation.required - Whether client attestation is required (will throw if missing)
 * @param options.clientAttestation.ensureConfirmationKeyMatchesDpopKey - Whether to verify DPoP and client attestation use the same key
 * @param options.request - The HTTP request object containing URL and headers
 * @param options.now - Optional date for time-based validation (defaults to current time)
 *
 * @returns A promise resolving to verification results containing:
 * - `jar` - Verified JAR request including decoded payload and signer (if JAR was provided)
 * - `dpop` - Verified DPoP information including JWK and thumbprint (if DPoP was provided)
 * - `clientAttestation` - Verified client attestation JWTs (if client attestation was provided)
 *
 * @throws {Oauth2Error} When JAR JWT verification fails
 * @throws {Oauth2Error} When JAR client_id doesn't match request client_id
 * @throws {Oauth2Error} When JAR request object is encrypted (not supported)
 * @throws {Oauth2Error} When DPoP is required but missing
 * @throws {Oauth2Error} When client attestation is required but missing
 * @throws {Oauth2Error} When client_id doesn't match between request and client attestation
 * @throws {Oauth2Error} When DPoP and client attestation keys don't match (if ensureConfirmationKeyMatchesDpopKey is true)
 * @throws {Oauth2Error} When any JWT signature verification fails
 * @throws {Oauth2Error} When any JWT is expired or has invalid claims
 *
 * @example
 * ```typescript
 * // First parse the PAR request
 * const parsed = await parsePushedAuthorizationRequest({
 *   request: httpRequest,
 *   callbacks: { fetch }
 * });
 *
 * // Then verify with signer from federation metadata
 * const result = await verifyPushedAuthorizationRequest({
 *   authorizationRequest: parsed.authorizationRequest,
 *   authorizationServerMetadata: { issuer: 'https://auth.example.com' },
 *   callbacks: { hash: hashCallback, verifyJwt: verifyJwtCallback },
 *   authorizationRequestJwt: parsed.jar ? {
 *     jwt: parsed.jar.jwt,
 *     signer: clientSignerFromFederation
 *   } : undefined,
 *   dpop: parsed.dpop,
 *   clientAttestation: parsed.clientAttestation,
 *   request: httpRequest
 * });
 *
 * console.log(result.jar?.authorizationRequestPayload.scope);
 * console.log(result.dpop?.jwkThumbprint);
 * ```
 */
export async function verifyPushedAuthorizationRequest(
  options: VerifyPushedAuthorizationRequestOptions,
): Promise<VerifyPushedAuthorizationRequestReturn> {
  let jar: VerifiedJarRequest | undefined;

  if (options.authorizationRequestJwt) {
    jar = await verifyJarRequest({
      authorizationRequestJwt: options.authorizationRequestJwt.jwt,
      callbacks: options.callbacks,
      jarRequestParams: options.authorizationRequest,
      jwtSigner: options.authorizationRequestJwt.signer,
    });
  }

  const { clientAttestation, dpop } = await verifyAuthorizationRequest(options);

  return {
    clientAttestation,
    dpop,
    jar,
  };
}
