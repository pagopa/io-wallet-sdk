import { encodeToBase64Url } from '@openid4vc/utils'
import { AuthorizationServerMetadata, CallbackContext, RequestDpopOptions } from "@openid4vc/oauth2";
import { createPkce } from '../pkce';
import { AuthorizationRequest, PushedAuthorizationRequestSigned } from './z-authorization-request';

const JWT_EXPIRY_SECONDS = 3600; // 1 hour
const RANDOM_BYTES_SIZE = 32;

export interface CreatePushedAuthorizationRequestOptions {
  /**
   * Callback context mostly for crypto related functionality
   */
  callbacks: Pick<CallbackContext, 'hash' | 'generateRandom' | 'signJwt' >

  codeChallengeMethodsSupported: AuthorizationServerMetadata["code_challenge_methods_supported"]

  /**
   * MUST be set to the thumbprint of the jwk value in the cnf parameter inside the Wallet Attestation.
   */
  clientId: string

  /**
   * It MUST be set to the identifier of the Credential Issuer.
   */
  audience: string

  /**
   * Scope to request for the authorization request
   */
  scope: string

  /**
   * It MUST be one of the supported values (response_modes_supported) provided in the metadata of the Credential Issuer.
   */
  responseMode: string

  /**
   * Redirect uri to include in the authorization request
   */
  redirectUri: string

  /**
   * Allows clients to specify their fine-grained authorization requirements using the expressiveness of JSON data structures
   */
  authorization_details: Record<string, unknown>

  /**
   * Code verifier to use for pkce. If not provided a value will generated when pkce is supported
   */
  pkceCodeVerifier?: string

  /**
   * DPoP options
   */
  dpop: RequestDpopOptions
}

export async function createPushedAuthorizationRequest(options: CreatePushedAuthorizationRequestOptions) : Promise<PushedAuthorizationRequestSigned> {

  // PKCE
  const pkce = await createPkce({
    allowedCodeChallengeMethods: options.codeChallengeMethodsSupported,
    callbacks: options.callbacks,
    codeVerifier: options.pkceCodeVerifier,
  });

  const authorizationRequest: AuthorizationRequest = {
    response_type: 'code',
    response_mode: options.responseMode,
    state: encodeToBase64Url( await options.callbacks.generateRandom(RANDOM_BYTES_SIZE)),
    client_id: options.clientId,
    redirect_uri: options.redirectUri,
    scope: options.scope,
    authorization_details: options.authorization_details,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: pkce.codeChallengeMethod,
  }

  const { dpop } = options;
  if (!dpop.signer.alg || !dpop.signer.publicJwk?.kid) {
    throw new Error('DPoP signer must have alg and publicJwk.kid properties');
  }

  const iat = Math.floor(Date.now())
  const requestJwt = await options.callbacks.signJwt(dpop.signer, {
      header: {
        alg: dpop.signer.alg,
        kid: dpop.signer.publicJwk.kid,
        typ: "jwt",
      },
      payload: {
        aud: options.audience,
        exp: iat + JWT_EXPIRY_SECONDS,
        iat,
        iss: dpop.signer.publicJwk.kid,
        jti: encodeToBase64Url(await options.callbacks.generateRandom(RANDOM_BYTES_SIZE)),
        ...authorizationRequest
      },
    });

  return {
    client_id: options.clientId,
    request: requestJwt.jwt
  }
}
