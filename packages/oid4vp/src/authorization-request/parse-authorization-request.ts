import {
  type CallbackContext,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  JwtParseError,
  JwtSigner,
  ValidationError,
  decodeJwt,
  dispatchByVersion,
  verifyJwt,
} from "@pagopa/io-wallet-utils";

import { Oid4vpError, ParseAuthorizeRequestError } from "../errors";
import {
  ClientIdPrefix,
  extractClientIdPrefix,
  validateAuthorizationRequestClientBinding,
} from "./client-id-prefix";
import {
  X509CertificateBinding,
  validateCertificateEndpoints,
} from "./validate-certificate-endpoints";
import {
  Openid4vpAuthorizationRequestHeader,
  Openid4vpAuthorizationRequestHeaderV1_3,
  Openid4vpAuthorizationRequestPayload,
  zOpenid4vpAuthorizationRequestHeaderV1_0,
  zOpenid4vpAuthorizationRequestHeaderV1_3,
  zOpenid4vpAuthorizationRequestPayload,
} from "./z-authorization-request";

export {
  type ClientIdParts,
  ClientIdPrefix,
  createX509HashClientId,
  extractClientIdPrefix,
} from "./client-id-prefix";

/**
 * Retrieves the public key for verifying the Request Object JWT signature
 * according to IT Wallet specifications.
 *
 * Prefix routing:
 * 1. If client_id uses x509_hash: use x5c certificate chain from header.
 * 2. If client_id uses openid_federation or no prefix: return a federation signer;
 *    if trust_chain is present it is forwarded, otherwise the verifyJwt callback is
 *    responsible for reconstructing the chain from client_id.
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
      ...(header.trust_chain && { trustChain: header.trust_chain }),
      x5c: header.x5c,
    };
  }

  throw new ParseAuthorizeRequestError(
    "Unable to determine public key for Request Object verification with client_id prefix: " +
      clientIdPrefix,
  );
}

export interface ParseAuthorizeRequestOptions {
  /**
   * Optional callback context for JWT signature verification and hashing x509 client_id for digest comparison.
   * If not provided, signature verification is skipped or hash skips the x509_hash digest comparison.
   */
  callbacks?: Partial<Pick<CallbackContext, "hash" | "verifyJwt">> &
    Partial<X509CertificateBinding>;

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

  /**
   * X.509 context extracted from the Request Object header when `x5c` is present.
   */
  x509Certificate?: {
    leafCertificate: string;
    x5c: [string, ...string[]];
  };
}

/**
 * Parses and optionally verifies a JWT containing an OpenID4VP Request Object.
 *
 * This method decodes the Request Object JWT and validates its structure. If the `verifyJwt`
 * callback is provided, it also verifies the JWT signature using the public key obtained
 * according to IT Wallet specifications:
 * 1. If client_id uses x509_hash: pass an x5c signer to the callback.
 * 2. If client_id uses openid_federation or a legacy HTTPS identifier, pass a federation signer;
 *    trust_chain is forwarded when present, otherwise the callback must reconstruct the chain from client_id.
 *
 * For x509_hash client identifiers, x5c is always required. When `callbacks.hash` is provided,
 * this method also checks the SHA-256 base64url certificate digest embedded in client_id.
 *
 * Security: If `verifyJwt` callback is not provided in options, JWT signature verification is skipped.
 *
 * @param options {@link ParseAuthorizeRequestOptions}
 * @returns A {@link ParsedAuthorizeRequestResult} containing the RP required credentials payload and the {@link Openid4vpAuthorizationRequestHeader} JWT header
 * @throws {ValidationError} in case there are errors validating the Request Object structure
 * @throws {JwtParseError} in case the request object jwt is malformed (e.g missing header, bad encoding)
 * @throws {@link ParseAuthorizeRequestError} in case the JWT signature is invalid (when verifyJwt is provided) or there are unexpected errors
 */
export async function parseAuthorizeRequest(
  options: ParseAuthorizeRequestOptions,
): Promise<ParsedAuthorizeRequestResult> {
  try {
    const headerSchema = dispatchByVersion<
      | typeof zOpenid4vpAuthorizationRequestHeaderV1_0
      | typeof zOpenid4vpAuthorizationRequestHeaderV1_3
    >(options.config.itWalletSpecsVersion, {
      [ItWalletSpecsVersion.V1_0]: () =>
        zOpenid4vpAuthorizationRequestHeaderV1_0,
      [ItWalletSpecsVersion.V1_3]: () =>
        zOpenid4vpAuthorizationRequestHeaderV1_3,
      [ItWalletSpecsVersion.V1_4]: () =>
        zOpenid4vpAuthorizationRequestHeaderV1_3,
    });

    const decoded = decodeJwt({
      errorMessagePrefix: "Error decoding authorization request JWT:",
      headerSchema,
      jwt: options.requestObjectJwt,
      payloadSchema: zOpenid4vpAuthorizationRequestPayload,
    });

    if (options.config.itWalletSpecsVersion !== ItWalletSpecsVersion.V1_0) {
      await validateAuthorizationRequestClientBinding({
        hash: options.callbacks?.hash,
        header: decoded.header as Openid4vpAuthorizationRequestHeaderV1_3,
        payload: decoded.payload,
      });
    }

    const x5c =
      "x5c" in decoded.header &&
      Array.isArray(decoded.header.x5c) &&
      decoded.header.x5c.length > 0
        ? (decoded.header.x5c as [string, ...string[]])
        : undefined;

    if (x5c && options.callbacks?.getX509CertificateMetadata) {
      await validateCertificateEndpoints({
        callbacks: {
          getX509CertificateMetadata:
            options.callbacks.getX509CertificateMetadata,
        },
        certificate: x5c[0],
        endpoints: [
          { name: "request_uri", uri: decoded.payload.request_uri },
          { name: "response_uri", uri: decoded.payload.response_uri },
        ],
      });
    }

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
      ...(x5c && {
        x509Certificate: {
          leafCertificate: x5c[0],
          x5c,
        },
      }),
    };
  } catch (error) {
    if (
      error instanceof ItWalletSpecsVersionError ||
      error instanceof ValidationError ||
      error instanceof Oauth2JwtParseError ||
      error instanceof Oid4vpError
    )
      throw error;
    throw new ParseAuthorizeRequestError(
      `Unexpected error during Request Object parsing: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
