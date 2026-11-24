import {
  type CallbackContext,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  type RequestDpopOptions,
  addSecondsToDate,
  dateToSeconds,
  dispatchByVersion,
  encodeToBase64Url,
} from "@pagopa/io-wallet-utils";

import type { BaseAuthorizationServerMetadata } from "../authorization-server-metadata";

import { PushedAuthorizationRequestError } from "../errors";
import { createPkce } from "../pkce";
import { requestObjectTyps } from "./request-object-typ";
import {
  AuthorizationRequestV1_0,
  AuthorizationRequestV1_3,
  AuthorizationRequestV1_4,
  MAX_PUSHED_AUTHORIZATION_REQUEST_TTL_SECONDS,
  PushedAuthorizationRequest,
  PushedAuthorizationRequestSigned,
  PushedAuthorizationRequestUnsigned,
  PushedAuthorizationRequestUnsignedV1_0,
  PushedAuthorizationRequestUnsignedV1_3,
  PushedAuthorizationRequestUnsignedV1_4,
  zAuthorizationRequestV1_0,
  zAuthorizationRequestV1_3,
  zAuthorizationRequestV1_4,
} from "./z-authorization-request";

const RANDOM_BYTES_SIZE = 32;

type AuthorizationRequest =
  | AuthorizationRequestV1_0
  | AuthorizationRequestV1_3
  | AuthorizationRequestV1_4;

interface BaseCreatePushedAuthorizationRequestOptions<
  V extends ItWalletSpecsVersion,
> {
  /**
   * It MUST be set to the identifier of the Credential Issuer.
   */
  audience: string;

  /**
   * Allows clients to specify their fine-grained authorization requirements using the expressiveness of JSON data structures
   */
  authorization_details?: AuthorizationRequest["authorization_details"];

  /**
   * Authorization Server metadata for conditional JAR signing.
   * When require_signed_request_object is true, creates a signed JWT (JAR).
   * When require_signed_request_object is false, creates an unsigned authorization request.
   * Defaults to false (unsigned) if not provided.
   *
   * @see {@link https://datatracker.ietf.org/doc/html/rfc9101#section-10.5 RFC 9101 Section 10.5}
   */
  authorizationServerMetadata?: {
    require_signed_request_object?: boolean;
  };

  /**
   * Callback context mostly for crypto related functionality
   */
  callbacks: Pick<CallbackContext, "generateRandom" | "hash" | "signJwt">;

  /**
   * MUST be set to the thumbprint of the jwk value in the cnf parameter inside the Wallet Attestation.
   */
  clientId: string;

  codeChallengeMethodsSupported: BaseAuthorizationServerMetadata["code_challenge_methods_supported"];

  config: IoWalletSdkConfig<V>;

  /**
   * DPoP options. Required when `require_signed_request_object` is `true`
   * (enforced at the type level via function overloads). Not used in the
   * unsigned path and can be omitted.
   */
  dpop?: RequestDpopOptions;

  /**
   * Expiration time of the JWT. If not provided 1 hour will be added to the `issuedAt`
   */
  expiresAt?: Date;

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date;

  /**
   * Optional issuer state from the Credential Offer authorization_code grant.
   * Serialized as issuer_state in the authorization request.
   */
  issuerState?: string;

  /**
   * jti parameter to use for PAR. If not provided a value will generated automatically
   */
  jti?: string;

  /**
   * Code verifier to use for pkce. If not provided a value will generated when pkce is supported
   */
  pkceCodeVerifier?: string;

  /**
   * Redirect uri to include in the authorization request
   */
  redirectUri: string;

  /**
   * Scope to request for the authorization request
   */
  scope?: string;

  /**
   * state parameter to use for PAR. If not provided a value will generated automatically
   */
  state?: string;
}

export interface CreatePushedAuthorizationRequestOptionsV1_0 extends BaseCreatePushedAuthorizationRequestOptions<ItWalletSpecsVersion.V1_0> {
  /**
   * It MUST be one of the supported values (response_modes_supported) provided in the metadata of the Credential Issuer.
   */
  responseMode: string;
}

export type CreatePushedAuthorizationRequestOptionsV1_3 =
  BaseCreatePushedAuthorizationRequestOptions<ItWalletSpecsVersion.V1_3>;

export interface CreatePushedAuthorizationRequestOptionsV1_4 extends BaseCreatePushedAuthorizationRequestOptions<ItWalletSpecsVersion.V1_4> {
  /**
   * REQUIRED. At least one `openid_credential` object is required.
   */
  authorization_details: AuthorizationRequestV1_4["authorization_details"];

  /**
   * REQUIRED. Scope advertised for the requested Credential Configuration in the
   * Credential Issuer metadata or in the Credential Offer.
   */
  scope: string;
}

export type CreatePushedAuthorizationRequestOptions =
  | CreatePushedAuthorizationRequestOptionsV1_0
  | CreatePushedAuthorizationRequestOptionsV1_3
  | CreatePushedAuthorizationRequestOptionsV1_4;

type CreatePushedAuthorizationRequestOptionsSigned<
  TOptions extends CreatePushedAuthorizationRequestOptions,
> = {
  authorizationServerMetadata: { require_signed_request_object: true };
  dpop: RequestDpopOptions;
} & TOptions;

type CreatePushedAuthorizationRequestOptionsUnsigned<
  TOptions extends CreatePushedAuthorizationRequestOptions,
> = {
  authorizationServerMetadata: { require_signed_request_object: false };
} & TOptions;

/**
 * Creates a Pushed Authorization Request (PAR) for OAuth 2.0 authorization flows.
 *
 * This function conditionally creates signed JWT-Secured Authorization Requests (JAR)
 * based on the Authorization Server's `require_signed_request_object` metadata parameter
 * as defined in RFC 9101. The signing behavior enables compliance with both OAuth 2.0 PAR
 * (RFC 9126) and IT-Wallet v1.3.3 specifications.
 *
 * **Conditional JAR Signing:**
 * - When `require_signed_request_object` is `true`: Creates a signed JAR
 * - When `require_signed_request_object` is `false`: Creates an unsigned authorization request
 * - When metadata not provided: Defaults to unsigned (permissive)
 *
 * **Security Note:**
 * Disabling JAR signing (setting `require_signed_request_object: false`) should only be done
 * when the Authorization Server explicitly supports and allows unsigned requests. Signed
 * requests provide protection against request tampering and replay attacks.
 *
 * @param options - Configuration for creating the PAR
 * @param options.audience - The identifier of the Credential Issuer (used as JWT aud claim)
 * @param options.authorization_details - Fine-grained authorization requirements using JSON data structures
 * @param options.authorizationServerMetadata - Authorization Server metadata for conditional JAR signing
 * @param options.authorizationServerMetadata.require_signed_request_object -
 *   When `true`, creates a signed JAR. When `false`, creates an unsigned authorization request.
 *   Defaults to `false` if not provided (permissive).
 * @param options.callbacks - Cryptographic callback functions (generateRandom, hash, signJwt)
 * @param options.clientId - Thumbprint of the jwk value in the cnf parameter inside Wallet Attestation
 * @param options.codeChallengeMethodsSupported - Supported code challenge methods from Authorization Server
 * @param options.dpop - DPoP signer options (alg, publicJwk.kid). Required when JAR signing is enabled; omitted for unsigned requests
 * @param options.jti - Optional JWT ID for PAR (auto-generated if not provided)
 * @param options.pkceCodeVerifier - Optional PKCE code verifier (auto-generated if not provided)
 * @param options.redirectUri - Redirect URI for the authorization response
 * @param options.config - Italian Wallet specification version used to build the request shape
 * @param options.responseMode - Response mode (v1.0 only, must be supported by Credential Issuer)
 * @param options.scope - OAuth 2.0 scope to request
 * @param options.state - Optional state parameter (auto-generated if not provided)
 * @param options.expiresAt - Optional JWT expiration time (defaults to 5 minutes from issuedAt and MUST NOT exceed 300 seconds from issuedAt)
 * @param options.issuedAt - Optional JWT issued at time (defaults to current time)
 *
 * @returns A promise resolving to either:
 *   - `PushedAuthorizationRequestSigned` when JAR signing is required (contains `request` JWT)
 *   - version-specific unsigned PAR when JAR signing is not required (contains `authorizationRequest` object)
 *
 * @throws {PushedAuthorizationRequestError} If DPoP signer is missing required properties (alg, publicJwk.kid)
 * @throws {PushedAuthorizationRequestError} If PKCE code challenge method is not supported
 * @throws {PushedAuthorizationRequestError} If `expiresAt` is not after `issuedAt`
 * @throws {PushedAuthorizationRequestError} If `expiresAt` is more than 300 seconds after `issuedAt`
 * @throws {ZodError} If authorization request parameters fail validation
 *
 * @example
 * // Example 1: Create signed PAR for IT-Wallet v1.0 (explicit)
 * const config = new IoWalletSdkConfig({
 *   itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
 * });
 *
 * const signedPar = await createPushedAuthorizationRequest({
 *   audience: 'https://issuer.example.com',
 *   callbacks: { generateRandom, hash, signJwt },
 *   clientId: 'wallet_client_thumbprint',
 *   codeChallengeMethodsSupported: ['S256'],
 *   config,
 *   dpop: { signer: { alg: 'ES256', publicJwk: { kid: 'key-1' } } },
 *   redirectUri: 'https://wallet.example.com/callback',
 *   responseMode: 'form_post.jwt',
 *   scope: 'openid',
 *   authorizationServerMetadata: {
 *     require_signed_request_object: true  // Creates signed JAR
 *   }
 * });
 * // signedPar.request contains the signed JWT
 *
 * @example
 * // Example 2: Create unsigned PAR for IT-Wallet v1.3 (when Authorization Server allows it)
 * const config = new IoWalletSdkConfig({
 *   itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
 * });
 *
 * const unsignedPar = await createPushedAuthorizationRequest({
 *   audience: 'https://issuer.example.com',
 *   callbacks: { generateRandom, hash, signJwt },
 *   clientId: 'wallet_client_thumbprint',
 *   codeChallengeMethodsSupported: ['S256'],
 *   config,
 *   redirectUri: 'https://wallet.example.com/callback',
 *   scope: 'openid',
 *   authorizationServerMetadata: {
 *     require_signed_request_object: false  // Creates unsigned request — dpop not needed
 *   }
 * });
 * // unsignedPar.authorizationRequest contains the plain object
 *
 * @example
 * // Example 3: Default behavior for IT-Wallet v1.0 (no metadata - unsigned)
 * const config = new IoWalletSdkConfig({
 *   itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
 * });
 *
 * const par = await createPushedAuthorizationRequest({
 *   audience: 'https://issuer.example.com',
 *   callbacks: { generateRandom, hash, signJwt },
 *   clientId: 'wallet_client_thumbprint',
 *   codeChallengeMethodsSupported: ['S256'],
 *   config,
 *   redirectUri: 'https://wallet.example.com/callback',
 *   responseMode: 'form_post.jwt',
 *   scope: 'openid'
 *   // No authorizationServerMetadata — defaults to unsigned, dpop not needed
 * });
 * // par.authorizationRequest contains the plain object (permissive default)
 *
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9126 RFC 9126 - OAuth 2.0 Pushed Authorization Requests}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9101 RFC 9101 - JWT-Secured Authorization Request (JAR)}
 * @see {@link https://datatracker.ietf.org/doc/html/rfc9101#section-10.5 RFC 9101 Section 10.5 - require_signed_request_object}
 */
// Function overloads for type narrowing based on require_signed_request_object
export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptionsSigned<CreatePushedAuthorizationRequestOptions>,
): Promise<PushedAuthorizationRequestSigned>;

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptionsUnsigned<CreatePushedAuthorizationRequestOptionsV1_0>,
): Promise<PushedAuthorizationRequestUnsignedV1_0>;

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptionsV1_0,
): Promise<
  PushedAuthorizationRequestSigned | PushedAuthorizationRequestUnsignedV1_0
>;

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptionsUnsigned<CreatePushedAuthorizationRequestOptionsV1_3>,
): Promise<PushedAuthorizationRequestUnsignedV1_3>;

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptionsV1_3,
): Promise<
  PushedAuthorizationRequestSigned | PushedAuthorizationRequestUnsignedV1_3
>;

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptionsUnsigned<CreatePushedAuthorizationRequestOptionsV1_4>,
): Promise<PushedAuthorizationRequestUnsignedV1_4>;

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptionsV1_4,
): Promise<
  PushedAuthorizationRequestSigned | PushedAuthorizationRequestUnsignedV1_4
>;

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptions,
): Promise<PushedAuthorizationRequest>;

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptions,
): Promise<PushedAuthorizationRequest> {
  const pkce = await createPkce({
    allowedCodeChallengeMethods: options.codeChallengeMethodsSupported,
    callbacks: options.callbacks,
    codeVerifier: options.pkceCodeVerifier,
  });

  const baseAuthorizationRequest = {
    authorization_details: options.authorization_details,
    client_id: options.clientId,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: pkce.codeChallengeMethod,
    ...(options.issuerState !== undefined
      ? { issuer_state: options.issuerState }
      : {}),
    jti:
      options.jti ??
      encodeToBase64Url(
        await options.callbacks.generateRandom(RANDOM_BYTES_SIZE),
      ),
    redirect_uri: options.redirectUri,
    response_type: "code",
    scope: options.scope,
    state:
      options.state ??
      encodeToBase64Url(
        await options.callbacks.generateRandom(RANDOM_BYTES_SIZE),
      ),
  };

  const authorizationRequest = parseAuthorizationRequestByVersion(
    options,
    baseAuthorizationRequest,
  );

  const requireSigned =
    options.authorizationServerMetadata?.require_signed_request_object ?? false;

  if (requireSigned) {
    const { dpop } = options;
    if (!dpop || !dpop.signer.alg || !dpop.signer.publicJwk?.kid) {
      throw new PushedAuthorizationRequestError(
        "DPoP signer must have alg and publicJwk.kid properties",
      );
    }

    const iat = options.issuedAt ?? new Date();
    const maxExp = addSecondsToDate(
      iat,
      MAX_PUSHED_AUTHORIZATION_REQUEST_TTL_SECONDS,
    );
    const exp = options.expiresAt ?? maxExp;

    if (exp <= iat) {
      throw new PushedAuthorizationRequestError(
        "Request object exp must be after iat",
      );
    }
    if (exp > maxExp) {
      throw new PushedAuthorizationRequestError(
        `Request object lifetime must not exceed ${MAX_PUSHED_AUTHORIZATION_REQUEST_TTL_SECONDS} seconds`,
      );
    }

    const requestJwt = await options.callbacks.signJwt(dpop.signer, {
      header: {
        alg: dpop.signer.alg,
        kid: dpop.signer.publicJwk.kid,
        typ: requestObjectTyps[options.config.itWalletSpecsVersion].sign,
      },
      payload: {
        aud: options.audience,
        exp: dateToSeconds(exp),
        iat: dateToSeconds(iat),
        iss: dpop.signer.publicJwk.kid,
        ...authorizationRequest,
      },
    });

    return {
      client_id: options.clientId,
      pkceCodeVerifier: pkce.codeVerifier,
      request: requestJwt.jwt,
    };
  }

  return {
    authorizationRequest,
    client_id: options.clientId,
    pkceCodeVerifier: pkce.codeVerifier,
  } as PushedAuthorizationRequestUnsigned;
}

function parseAuthorizationRequestByVersion(
  options: CreatePushedAuthorizationRequestOptions,
  baseAuthorizationRequest: Partial<AuthorizationRequest>,
): AuthorizationRequest {
  return dispatchByVersion<AuthorizationRequest>(
    options.config.itWalletSpecsVersion,
    {
      [ItWalletSpecsVersion.V1_0]: () =>
        zAuthorizationRequestV1_0.parse({
          ...baseAuthorizationRequest,
          response_mode: (
            options as CreatePushedAuthorizationRequestOptionsV1_0
          ).responseMode,
        }),
      [ItWalletSpecsVersion.V1_3]: () =>
        zAuthorizationRequestV1_3.parse(baseAuthorizationRequest),
      [ItWalletSpecsVersion.V1_4]: () =>
        zAuthorizationRequestV1_4.parse(baseAuthorizationRequest),
    },
  );
}
