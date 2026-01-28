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
