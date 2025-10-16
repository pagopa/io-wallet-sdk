import {
  CallbackContext,
  Oauth2JwtParseError,
  RequestDpopOptions,
  decodeJwt,
} from "@openid4vc/oauth2";
import { ValidationError } from "@openid4vc/utils";

import { ParseAuthorizeRequestError } from "../errors";
import {
  AuthorizationRequestObject,
  zOpenid4vpAuthorizationRequest,
} from "./z-request-object";

export interface ParseAuthorizeRequestOptions {
  /**
   * Callback context for signature verification.
   */
  callbacks: Pick<CallbackContext, "verifyJwt">;

  /**
   * DPoP options
   */
  dpop: RequestDpopOptions;

  /**
   * The Authorization Request Object JWT.
   */
  requestObjectJwt: string;
}

/**
 * This method verifies a JWT containing a Request Object and returns its
 * decoded value for further processing
 * @param options {@link ParseAuthorizeRequestOptions}
 * @returns An {@link AuthorizationRequestObject} containing the RP required
 *          credentials
 * @throws {@link ValidationError} in case there are errors validating the Request Object structure
 * @throws {@link Oauth2JwtParseError} in case the request object jwt is malformed (e.g missing header, bad encoding)
 * @throws {@link ParseAuthorizeRequestError} in case the JWT signature is invalid or there are unexpected errors
 */
export async function parseAuthorizeRequest(
  options: ParseAuthorizeRequestOptions,
): Promise<AuthorizationRequestObject> {
  try {
    const decoded = decodeJwt({
      jwt: options.requestObjectJwt,
      payloadSchema: zOpenid4vpAuthorizationRequest,
    });
    const verificationResult = await options.callbacks.verifyJwt(
      options.dpop.signer,
      {
        compact: options.requestObjectJwt,
        header: decoded.header,
        payload: decoded.payload,
      },
    );

    if (!verificationResult.verified)
      throw new ParseAuthorizeRequestError(
        "Error verifying Request Object signature",
      );

    return decoded.payload;
  } catch (error) {
    if (
      error instanceof ValidationError ||
      error instanceof Oauth2JwtParseError
    )
      throw error;
    throw new ParseAuthorizeRequestError(
      `Unexpected error during Request Object parsing: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
