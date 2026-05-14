import {
  CallbackContext,
  JwtSigner,
  Oauth2JwtParseError,
  verifyJwt,
} from "@openid4vc/oauth2";
import { decodeJwt } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  ValidationError,
  dispatchByVersion,
} from "@pagopa/io-wallet-utils";

import { ParseAuthorizeRequestError } from "../errors";
import {
  Openid4vpAuthorizationRequestHeader,
  Openid4vpAuthorizationRequestPayload,
  zOpenid4vpAuthorizationRequestHeaderV1_0,
  zOpenid4vpAuthorizationRequestHeaderV1_3,
  zOpenid4vpAuthorizationRequestPayload,
} from "./z-authorization-request";

/**
 * Enum representing the client_id prefix types according to IT Wallet specifications
 */
export enum ClientIdPrefix {
  NONE = "none",
  OPENID_FEDERATION = "openid_federation",
  X509_HASH = "x509_hash",
}

export interface ClientIdParts {
  prefix: ClientIdPrefix | string;
  clientId: string;
}

/**
 * Extracts the prefix and clean clientId from a client_id string.
 * @param clientId - The client_id from the request object
 * @returns A {@link ClientIdParts} object with the resolved prefix and unprefixed clientId
 */
export function extractClientIdPrefix(clientId: string): ClientIdParts {
  const colonIndex = clientId.indexOf(":");

  if (colonIndex === -1) {
    return { prefix: ClientIdPrefix.NONE, clientId };
  }

  const rawPrefix = clientId.slice(0, colonIndex);
  const rest = clientId.slice(colonIndex + 1);

  if (rawPrefix === ClientIdPrefix.X509_HASH) {
    return { prefix: ClientIdPrefix.X509_HASH, clientId: rest };
  }
  if (rawPrefix === ClientIdPrefix.OPENID_FEDERATION) {
    return { prefix: ClientIdPrefix.OPENID_FEDERATION, clientId: rest };
  }

  return { prefix: rawPrefix, clientId: rest };
}

/**
 * Retrieves the public key for verifying the Request Object JWT signature
 * according to IT Wallet specifications.
 *
 * Priority order:
 * 1. If client_id has x509_hash prefix: use x5c certificate chain from header
 * 2. If client_id has openid_federation prefix or no prefix: return a federation signer; if trust_chain
 *    is present it is forwarded, otherwise the verifyJwt callback is responsible for reconstructing
 *    the chain from client_id
 *
 * @param options - Parse options containing decoded JWT
 * @returns The JWK to use for signature verification
 * @throws {ParseAuthorizeRequestError} When no valid public key can be found
 */
function getPublicKeyForVerification(options: {
  header: Openid4vpAuthorizationRequestHeader;
  payload: Openid4vpAuthorizationRequestPayload;
}): JwtSigner {
  const { header, payload } = options;

  const { prefix: clientIdPrefix } = extractClientIdPrefix(payload.client_id);

  // Priority 1: x509_hash prefix - use x5c certificate chain from header
  if (clientIdPrefix === ClientIdPrefix.X509_HASH) {
    if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
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

  // Priority 2: openid_federation prefix or no prefix - use trust_chain if present,
  // otherwise delegate chain reconstruction to the verifyJwt callback
  if (
    clientIdPrefix === ClientIdPrefix.OPENID_FEDERATION ||
    clientIdPrefix === ClientIdPrefix.NONE
  ) {
    if (!header.kid) {
      throw new ParseAuthorizeRequestError(
        "kid is required in JWT header for openid_federation client_id or no prefix",
      );
    }

    return {
      alg: header.alg,
      kid: header.kid,
      method: "federation" as const,
      ...(header.trust_chain && { trustChain: header.trust_chain }),
    };
  }

  throw new ParseAuthorizeRequestError(
    "Unable to determine public key for Request Object verification",
  );
}

export interface ParseAuthorizeRequestOptions {
  /**
   * Optional callback context for JWT signature verification.
   * If not provided, signature verification is skipped.
   */
  callbacks?: Pick<CallbackContext, "verifyJwt">;

  config: IoWalletSdkConfig;

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
  payload: Openid4vpAuthorizationRequestPayload;
}

/**
 * Parses and optionally verifies a JWT containing an OpenID4VP Request Object.
 *
 * This method decodes the Request Object JWT and validates its structure. If the `verifyJwt`
 * callback is provided, it also verifies the JWT signature using the public key obtained
 * according to IT Wallet specifications:
 * 1. If client_id has x509_hash prefix: use x5c certificate chain from header
 * 2. If client_id has openid_federation prefix or no prefix: pass a federation signer to the callback;
 *    trust_chain is forwarded when present, otherwise the callback must reconstruct the chain from client_id
 *
 * @param options {@link ParseAuthorizeRequestOptions}
 * @returns A {@link ParsedAuthorizeRequestResult} containing the RP required credentials payload and the {@link Openid4vpAuthorizationRequestHeader} JWT header
 * @throws {@link ValidationError} in case there are errors validating the Request Object structure
 * @throws {@link Oauth2JwtParseError} in case the request object jwt is malformed (e.g missing header, bad encoding)
 * @throws {@link ParseAuthorizeRequestError} in case the JWT signature is invalid (when verifyJwt is provided) or there are unexpected errors
 *
 * @security If `verifyJwt` callback is not provided in options, JWT signature verification is skipped.
 */
export async function parseAuthorizeRequest(
  options: ParseAuthorizeRequestOptions,
): Promise<ParsedAuthorizeRequestResult> {
  try {
    const headerSchema = dispatchByVersion<
      | typeof zOpenid4vpAuthorizationRequestHeaderV1_0
      | typeof zOpenid4vpAuthorizationRequestHeaderV1_3
    >("parseAuthorizeRequest", options.config.itWalletSpecsVersion, {
      [ItWalletSpecsVersion.V1_0]: () =>
        zOpenid4vpAuthorizationRequestHeaderV1_0,
      [ItWalletSpecsVersion.V1_3]: () =>
        zOpenid4vpAuthorizationRequestHeaderV1_3,
    });

    const decoded = decodeJwt({
      errorMessagePrefix: "Error decoding authorization request JWT:",
      headerSchema,
      jwt: options.requestObjectJwt,
      payloadSchema: zOpenid4vpAuthorizationRequestPayload,
    });

    if (options.callbacks?.verifyJwt) {
      const signer = getPublicKeyForVerification({
        header: decoded.header,
        payload: decoded.payload,
      });

      await verifyJwt({
        compact: options.requestObjectJwt,
        errorMessage: "Error verifying Request Object signature",
        header: decoded.header,
        payload: decoded.payload,
        signer,
        verifyJwtCallback: options.callbacks.verifyJwt,
      });
    }

    return {
      header: decoded.header,
      payload: decoded.payload,
    };
  } catch (error) {
    if (
      error instanceof ItWalletSpecsVersionError ||
      error instanceof ValidationError ||
      error instanceof Oauth2JwtParseError
    )
      throw error;
    throw new ParseAuthorizeRequestError(
      `Unexpected error during Request Object parsing: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
