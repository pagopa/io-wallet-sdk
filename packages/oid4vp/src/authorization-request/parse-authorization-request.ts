import {
  CallbackContext,
  JwtSigner,
  Oauth2JwtParseError,
  decodeJwt,
} from "@openid4vc/oauth2";
import { ValidationError } from "@openid4vc/utils";

import { ParseAuthorizeRequestError } from "../errors";
import {
  AuthorizationRequestObject,
  Openid4vpAuthorizationRequestHeader,
  zOpenid4vpAuthorizationRequestHeader,
  zOpenid4vpAuthorizationRequestPayload,
} from "./z-request-object";

/**
 * Enum representing the client_id prefix types according to IT Wallet specifications
 */
enum ClientIdPrefix {
  NONE = "none",
  OPENID_FEDERATION = "openid_federation",
  X509_HASH = "x509_hash",
}

/**
 * Extracts the prefix from a client_id string
 * @param clientId - The client_id from the request object
 * @returns The prefix type (x509_hash, openid_federation, or none)
 */
function extractClientIdPrefix(clientId: string): ClientIdPrefix {
  if (clientId.startsWith("x509_hash:")) {
    return ClientIdPrefix.X509_HASH;
  }
  if (clientId.startsWith("openid_federation:")) {
    return ClientIdPrefix.OPENID_FEDERATION;
  }
  return ClientIdPrefix.NONE;
}

/**
 * Retrieves the public key for verifying the Request Object JWT signature
 * according to IT Wallet specifications.
 *
 * Priority order:
 * 1. If client_id has x509_hash prefix: use x5c certificate chain from header
 * 2. If client_id has openid_federation prefix or no prefix: extract metadata from trust_chain in header
 *
 * @param options - Parse options containing decoded JWT
 * @returns The JWK to use for signature verification
 * @throws {ParseAuthorizeRequestError} When no valid public key can be found
 */
async function getPublicKeyForVerification(options: {
  header: Openid4vpAuthorizationRequestHeader;
  payload: AuthorizationRequestObject;
}): Promise<JwtSigner> {
  const { header, payload } = options;

  const clientIdPrefix = extractClientIdPrefix(payload.client_id);

  // Priority 1: x509_hash prefix - use x5c certificate chain from header
  if (clientIdPrefix === ClientIdPrefix.X509_HASH) {
    if (!header.x5c || header.x5c.length === 0) {
      throw new ParseAuthorizeRequestError(
        "x5c is required in JWT header for x509_hash client_id",
      );
    }

    return {
      alg: header.alg,
      kid: header.kid,
      method: "x5c" as const,
      x5c: header.x5c,
    };
  }

  // Priority 2: openid_federation prefix or no prefix - extract from trust_chain
  if (
    clientIdPrefix === ClientIdPrefix.OPENID_FEDERATION ||
    clientIdPrefix === ClientIdPrefix.NONE
  ) {
    if (!header.trust_chain) {
      throw new ParseAuthorizeRequestError(
        "trust_chain is required in JWT header for openid_federation client_id or no prefix",
      );
    }

    if (!header.kid) {
      throw new ParseAuthorizeRequestError(
        "kid is required in JWT header for openid_federation client_id or no prefix",
      );
    }

    return {
      alg: header.alg,
      kid: header.kid,
      method: "federation" as const,
      trustChain: header.trust_chain,
    };
  }

  throw new ParseAuthorizeRequestError(
    "Unable to determine public key for Request Object verification",
  );
}

export interface ParseAuthorizeRequestOptions {
  /**
   * Callback context for signature verification.
   */
  callbacks: Pick<CallbackContext, "verifyJwt">;

  /**
   * The Authorization Request Object JWT.
   */
  requestObjectJwt: string;
}

export interface ParsedAuthorizeRequestResult {
  /**
   * The JWT header of the authorization request object.
   */
  header: Openid4vpAuthorizationRequestHeader;
  /**
   * The parsed authorization request object.
   */
  payload: AuthorizationRequestObject;
}

/**
 * This method verifies a JWT containing a Request Object and returns its
 * decoded value for further processing.
 *
 * The public key for signature verification is obtained according to IT Wallet specifications:
 * 1. If client_id has x509_hash prefix: use x5c certificate chain from header
 * 2. If client_id has openid_federation prefix or no prefix: extract from header.trust_chain
 *
 * @param options {@link ParseAuthorizeRequestOptions}
 * @returns A {@link ParsedAuthorizeRequestResult} containing the RP required credentials payload and the {@link Openid4vpAuthorizationRequestHeader} JWT header
 * @throws {@link ValidationError} in case there are errors validating the Request Object structure
 * @throws {@link Oauth2JwtParseError} in case the request object jwt is malformed (e.g missing header, bad encoding)
 * @throws {@link ParseAuthorizeRequestError} in case the JWT signature is invalid or there are unexpected errors
 */
export async function parseAuthorizeRequest(
  options: ParseAuthorizeRequestOptions,
): Promise<ParsedAuthorizeRequestResult> {
  try {
    const decoded = decodeJwt({
      headerSchema: zOpenid4vpAuthorizationRequestHeader,
      jwt: options.requestObjectJwt,
      payloadSchema: zOpenid4vpAuthorizationRequestPayload,
    });

    const signer = await getPublicKeyForVerification({
      header: decoded.header,
      payload: decoded.payload,
    });

    const verificationResult = await options.callbacks.verifyJwt(signer, {
      compact: options.requestObjectJwt,
      header: decoded.header,
      payload: decoded.payload,
    });

    if (!verificationResult.verified)
      throw new ParseAuthorizeRequestError(
        "Error verifying Request Object signature",
      );

    return {
      header: decoded.header,
      payload: decoded.payload,
    };
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
