import {
  CallbackContext,
  Oauth2JwtParseError,
  RequestDpopOptions,
  decodeJwt,
} from "@openid4vc/oauth2";
import { ValidationError } from "@openid4vc/utils";

import { Oid4vpParsingError } from "../error/Oid4vpParsingError";
import { AuthorizationRequestParsingError } from "./errors";
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
      throw new AuthorizationRequestParsingError(
        "Error verifying Request Object signature",
      );

    return decoded.payload;
  } catch (error) {
    if (
      error instanceof Oauth2JwtParseError ||
      error instanceof ValidationError
    ) {
      throw new Oid4vpParsingError(error.message);
    }
    throw new AuthorizationRequestParsingError(
      `Unexpected error during Request Object parsing: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
