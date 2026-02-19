import { JwtSigner } from "@openid4vc/oauth2";

import { decodeJwt } from "../common/jwt/decode-jwt";
import { PushedAuthorizationRequestError } from "../errors";
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
  extends Omit<
    VerifyAuthorizationRequestOptions,
    "authorizationServerMetadata"
  > {
  /**
   * The authorization request JWT to verify. If this value was returned from `parsePushedAuthorizationRequest`
   * you MUST provide this value to ensure the JWT is verified.
   */
  authorizationRequestJwt?: {
    jwt: string;
    signer: JwtSigner;
  };

  /**
   * Authorization Server metadata for enforcing JAR signing policy.
   * Includes standard Authorization Server metadata plus require_signed_request_object.
   * When require_signed_request_object is true, the server will reject unsigned requests.
   * Defaults to false (permissive) if not provided.
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc9101#section-10.5 RFC 9101 Section 10.5}
   */
  authorizationServerMetadata: {
    require_signed_request_object?: boolean;
  } & VerifyAuthorizationRequestOptions["authorizationServerMetadata"];
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
 * 1. JAR signing policy enforcement (per RFC 9101 Section 10.5) - validates require_signed_request_object
 * 2. JAR request object verification (if provided) - validates JWT signature and claims
 * 3. RFC 9101 §4 claim validation - validates iss, aud, exp, iat claims
 * 4. IT-Wallet specific validations - iat age limits and key binding with wallet attestation
 * 5. DPoP proof verification (if provided) - validates proof of possession
 * 6. Client attestation verification - validates client identity
 *
 * **JAR Signing Policy (RFC 9101):**
 * When `authorizationServerMetadata.require_signed_request_object` is true:
 * - Rejects requests without signed JAR (downgrade attack protection)
 * - Rejects JAR with algorithm "none" (security requirement)
 * When false or omitted (default): accepts both signed and unsigned requests
 *
 * **Important:** Use `parsePushedAuthorizationRequest` first to extract the necessary
 * JWTs from request headers and body.
 *
 * @param options - The verification options
 * @param options.authorizationRequest - The authorization request parameters containing client_id
 * @param options.authorizationServerMetadata - Authorization server metadata
 * @param options.authorizationServerMetadata.issuer - Authorization server issuer URL
 * @param options.authorizationServerMetadata.require_signed_request_object - Whether to enforce JAR signing (defaults to false)
 * @param options.callbacks - Cryptographic callback functions for hash and JWT verification
 * @param options.authorizationRequestJwt - Optional JAR JWT and signer information
 * @param options.authorizationRequestJwt.jwt - The JAR JWT string from request parameter
 * @param options.authorizationRequestJwt.signer - The JWT signer for verification (from federation metadata)
 * @param options.dpop - Optional DPoP verification configuration
 * @param options.dpop.jwt - The DPoP JWT extracted from request headers
 * @param options.dpop.required - Whether DPoP is required (will throw if missing)
 * @param options.dpop.allowedSigningAlgs - Allowed signing algorithms for DPoP
 * @param options.clientAttestation - Optional client attestation verification configuration
 * @param options.clientAttestation.walletAttestationJwt - The wallet attestation JWT from headers
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
 * @throws {PushedAuthorizationRequestError} When require_signed_request_object is true but request is unsigned
 * @throws {PushedAuthorizationRequestError} When require_signed_request_object is true but JAR uses alg="none"
 * @throws {PushedAuthorizationRequestError} When iss claim doesn't match client_id (RFC 9101 §4)
 * @throws {PushedAuthorizationRequestError} When aud claim doesn't match authorization server issuer (RFC 9101 §4)
 * @throws {PushedAuthorizationRequestError} When exp claim is missing or expired (RFC 9101 §4)
 * @throws {PushedAuthorizationRequestError} When iat claim is missing, too old (>5 min), or in future (>60s)
 * @throws {PushedAuthorizationRequestError} When kid doesn't match between JAR and wallet attestation cnf.jwk
 * @throws {PushedAuthorizationRequestError} When cnf.jwk is missing from wallet attestation
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
 * // Example 1: Enforce signed JAR (strict mode)
 * const result = await verifyPushedAuthorizationRequest({
 *   authorizationRequest: parsed.authorizationRequest,
 *   authorizationServerMetadata: {
 *     issuer: 'https://auth.example.com',
 *     require_signed_request_object: true  // Reject unsigned requests
 *   },
 *   callbacks: { hash: hashCallback, verifyJwt: verifyJwtCallback },
 *   authorizationRequestJwt: {
 *     jwt: parsed.authorizationRequestJwt,
 *     signer: clientSignerFromFederation
 *   },
 *   request: httpRequest
 * });
 *
 * // Example 2: Accept both signed and unsigned (permissive mode)
 * const result = await verifyPushedAuthorizationRequest({
 *   authorizationRequest: parsed.authorizationRequest,
 *   authorizationServerMetadata: {
 *     issuer: 'https://auth.example.com',
 *     require_signed_request_object: false  // Accept unsigned requests
 *   },
 *   callbacks: { hash: hashCallback, verifyJwt: verifyJwtCallback },
 *   authorizationRequestJwt: parsed.authorizationRequestJwt ? {
 *     jwt: parsed.authorizationRequestJwt,
 *     signer: clientSignerFromFederation
 *   } : undefined,
 *   request: httpRequest
 * });
 * ```
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9101#section-10.5 RFC 9101 Section 10.5 - require_signed_request_object}
 */
export async function verifyPushedAuthorizationRequest(
  options: VerifyPushedAuthorizationRequestOptions,
): Promise<VerifyPushedAuthorizationRequestReturn> {
  // Check if signed request objects are required (default to false for permissive server behavior)
  const requireSigned =
    options.authorizationServerMetadata?.require_signed_request_object ?? false;

  // Enforce require_signed_request_object policy
  if (requireSigned && !options.authorizationRequestJwt) {
    throw new PushedAuthorizationRequestError(
      "Authorization Server requires signed request objects (JAR) per RFC 9101, but request does not include a signed JWT",
    );
  }

  let jar: VerifiedJarRequest | undefined;

  if (options.authorizationRequestJwt) {
    // Fail-fast: reject alg="none" before expensive signature verification (RFC 9101 Section 10.5)
    if (requireSigned) {
      const decoded = decodeJwt({ jwt: options.authorizationRequestJwt.jwt });
      if (decoded.header.alg === "none") {
        throw new PushedAuthorizationRequestError(
          'Authorization Server requires signed request objects, but JAR has algorithm "none"',
        );
      }
    }

    // Verify JAR signature and claims
    jar = await verifyJarRequest({
      authorizationRequestJwt: options.authorizationRequestJwt.jwt,
      callbacks: options.callbacks,
      jarRequestParams: options.authorizationRequest,
      jwtSigner: options.authorizationRequestJwt.signer,
      now: options.now,
    });

    // aud claim MUST identify this Authorization Server
    const issuer = options.authorizationServerMetadata.issuer;
    if (!issuer) {
      throw new PushedAuthorizationRequestError(
        "authorizationServerMetadata.issuer is required to validate the aud claim in the request JWT",
      );
    }
    const aud = jar.jwt.payload.aud;
    const audMatches =
      aud === issuer || (Array.isArray(aud) && aud.includes(issuer));
    if (!audMatches) {
      throw new PushedAuthorizationRequestError(
        "aud claim in request JWT does not match the authorization server issuer",
      );
    }
  }

  const { clientAttestation, dpop } = await verifyAuthorizationRequest(options);

  if (jar && clientAttestation) {
    const cnfJwk = clientAttestation.clientAttestation.payload.cnf.jwk;
    if (!cnfJwk) {
      throw new PushedAuthorizationRequestError(
        "Missing wallet attestation or cnf.jwk",
      );
    }
    // Validate kid match if present in both JAR header and cnf.jwk
    if (cnfJwk.kid !== undefined && jar.jwt.header.kid !== cnfJwk.kid) {
      throw new PushedAuthorizationRequestError(
        "kid in request JWT header does not match wallet attestation cnf.jwk kid",
      );
    }
  }

  return {
    clientAttestation,
    dpop,
    jar,
  };
}
