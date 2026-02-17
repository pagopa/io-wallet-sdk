import {
  CallbackContext,
  JwtSigner,
  decodeJwt,
  jwtSignerFromJwt,
  verifyJwt,
} from "@openid4vc/oauth2";

import { Oid4vciError } from "../errors";
import {
  AuthorizationResponse,
  zAuthorizationResponse,
} from "./z-authorization-response";

export interface VerifyAuthorizationResponseOptions {
  /**
   * Authorization response object containing the authorization
   * code, the issuer and the session's state
   */
  authorizationResponse: AuthorizationResponse;

  /**
   * The issuer the Wallet Instance started the
   * authorization flow (either via PAR or directly) with
   */
  iss: string;

  /**
   * The state sent by the Wallet Instance at the start
   * of the authorization flow (either via PAR or directly)
   */
  state: string;
}

export interface VerifyAuthorizationResponseFormPostJWTOptions {
  /**
   * Compact AuthorizaitonResponse JWT
   */
  authorizationResponseCompact: string;

  /**
   * Authorization Response object containing the authorization
   * code, the issuer and the session's state
   */
  authorizationResponseDecoded: ReturnType<
    typeof decodeJwt<undefined, typeof zAuthorizationResponse>
  >;

  /**
   * Callback for verifying the authorization jwt signature
   */
  callbacks: Pick<CallbackContext, "verifyJwt">;

  /**
   * The issuer the Wallet Instance started the
   * authorization flow (either via PAR or directly) with
   */
  iss: string;

  /**
   * Optional custom signer for verifying the MRTD PoP init response JWT.
   * If not provided, the library will attempt to verify using JWT header.
   */
  signer: JwtSigner;

  /**
   * The state sent by the Wallet Instance at the start
   * of the authorization flow (either via PAR or directly)
   */
  state: string;
}

/**
 * Utility that verifies if the returned Authorization Response's iss and state field match
 * the Authorization Session ones
 * @param options {@link VerifyAuthorizationResponseOptions}
 * @returns the {@link AuthorizationResponse} passed as an option
 * @throws {Oid4vciError} in case the iss or state field of the Authorization request don't
 *         match the provided ones
 */
export async function verifyAuthorizationResponse(
  options: VerifyAuthorizationResponseOptions,
): Promise<AuthorizationResponse> {
  if (options.authorizationResponse.iss !== options.iss)
    throw new Oid4vciError(
      `Response result iss doesn't match passed counterpart. Expected: ${options.iss}, Got: ${options.authorizationResponse.iss}`,
    );
  if (options.authorizationResponse.state !== options.state)
    throw new Oid4vciError(
      `Response result state doesn't match passed counterpart. Expected: ${options.state}, Got: ${options.authorizationResponse.state}`,
    );

  return options.authorizationResponse;
}

/**
 * Wrapper of {@link verifyAuthorizationResponse} that verifies the signature of the JWT containing
 * the authorization response and extracts the {@link AuthorizationResponse} payload
 * @param options {@link VerifyAuthorizationResponseFormPostJWTOptions}
 * @returns the {@link AuthorizationResponse} passed as an option
 * @throws {Oid4vciError} in case {@link verifyAuthorizationResponse} throws or in case
 *         signature verification fails
 */
export async function verifyAuthorizationResponseFormPostJWT(
  options: VerifyAuthorizationResponseFormPostJWTOptions,
): Promise<AuthorizationResponse> {
  try {
    const decodedJwt = options.authorizationResponseDecoded;

    await verifyJwt({
      compact: options.authorizationResponseCompact,
      errorMessage: "Error verifying JWT signature",
      header: decodedJwt.header,
      payload: decodedJwt.payload,

      signer:
        options.signer ??
        jwtSignerFromJwt({
          header: decodedJwt.header,
          payload: decodedJwt.payload,
        }),
      verifyJwtCallback: options.callbacks.verifyJwt,
    });

    return verifyAuthorizationResponse({
      authorizationResponse: options.authorizationResponseDecoded.payload,
      iss: options.iss,
      state: options.state,
    });
  } catch (error) {
    if (error instanceof Oid4vciError) throw error;

    throw new Oid4vciError(
      `Unexpected error verifying form post jwt: ${error instanceof Error ? `${error.name} : ${error.message}` : String(error)}`,
    );
  }
}
