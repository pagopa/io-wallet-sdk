import {
  AuthorizationServerMetadata,
  CallbackContext,
  RequestDpopOptions,
} from "@openid4vc/oauth2";
import { encodeToBase64Url } from "@openid4vc/utils";

import { createPkce } from "../pkce";
import {
  AuthorizationRequest,
  PushedAuthorizationRequestSigned,
  zAuthorizationRequest,
} from "./z-authorization-request";

const JWT_EXPIRY_SECONDS = 3600; // 1 hour
const RANDOM_BYTES_SIZE = 32;

export interface CreatePushedAuthorizationRequestOptions {
  /**
   * It MUST be set to the identifier of the Credential Issuer.
   */
  audience: string;

  /**
   * Allows clients to specify their fine-grained authorization requirements using the expressiveness of JSON data structures
   */
  authorization_details?: AuthorizationRequest["authorization_details"];

  /**
   * Callback context mostly for crypto related functionality
   */
  callbacks: Pick<CallbackContext, "generateRandom" | "hash" | "signJwt">;

  /**
   * MUST be set to the thumbprint of the jwk value in the cnf parameter inside the Wallet Attestation.
   */
  clientId: string;

  codeChallengeMethodsSupported: AuthorizationServerMetadata["code_challenge_methods_supported"];

  /**
   * DPoP options
   */
  dpop: RequestDpopOptions;

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
   * It MUST be one of the supported values (response_modes_supported) provided in the metadata of the Credential Issuer.
   */
  responseMode: string;

  /**
   * Scope to request for the authorization request
   */
  scope?: string;

  /**
   * state parameter to use for PAR. If not provided a value will generated automatically
   */
  state?: string;
}

export async function createPushedAuthorizationRequest(
  options: CreatePushedAuthorizationRequestOptions,
): Promise<PushedAuthorizationRequestSigned> {
  // PKCE
  const pkce = await createPkce({
    allowedCodeChallengeMethods: options.codeChallengeMethodsSupported,
    callbacks: options.callbacks,
    codeVerifier: options.pkceCodeVerifier,
  });

  const authorizationRequest = zAuthorizationRequest.parse({
    authorization_details: options.authorization_details,
    client_id: options.clientId,
    code_challenge: pkce.codeChallenge,
    code_challenge_method: pkce.codeChallengeMethod,
    redirect_uri: options.redirectUri,
    response_mode: options.responseMode,
    response_type: "code",
    scope: options.scope,
    state:
      options.state ??
      encodeToBase64Url(
        await options.callbacks.generateRandom(RANDOM_BYTES_SIZE),
      ),
  });

  const { dpop } = options;
  if (!dpop.signer.alg || !dpop.signer.publicJwk?.kid) {
    throw new Error("DPoP signer must have alg and publicJwk.kid properties");
  }

  const iat = Math.floor(Date.now());
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
      jti:
        options.jti ??
        encodeToBase64Url(
          await options.callbacks.generateRandom(RANDOM_BYTES_SIZE),
        ),
      ...authorizationRequest,
    },
  });

  return {
    client_id: options.clientId,
    pkceCodeVerifier: pkce.codeVerifier,
    request: requestJwt.jwt,
  };
}
