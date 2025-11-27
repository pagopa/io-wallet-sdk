import {
  CallbackContext,
  Jwk,
  Oauth2JwtParseError,
  decodeJwt,
} from "@openid4vc/oauth2";
import { ValidationError } from "@openid4vc/utils";
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";
import { z } from "zod";

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
  if (clientId.startsWith("x509_hash#")) {
    return ClientIdPrefix.X509_HASH;
  }
  if (clientId.startsWith("openid_federation#")) {
    return ClientIdPrefix.OPENID_FEDERATION;
  }
  return ClientIdPrefix.NONE;
}

/**
 * Extracts RP metadata from the OpenID Federation trust chain
 * @param trustChain - Array of JWT strings representing the trust chain
 * @returns The RP metadata extracted from the trust chain
 * @throws {ParseAuthorizeRequestError} When trust chain is invalid or metadata cannot be extracted
 */
async function extractRpMetadataFromTrustChain(
  trustChain: string[],
): Promise<ItWalletCredentialVerifierMetadata> {
  try {
    // The first JWT in the trust chain contains the RP's entity configuration
    // which includes the openid_credential_verifier metadata
    const rpEntityConfigurationJwt = trustChain[0];

    if (!rpEntityConfigurationJwt) {
      throw new ParseAuthorizeRequestError(
        "Trust chain is empty, cannot extract RP metadata",
      );
    }

    // Decode the entity configuration JWT (we don't need to verify it here,
    // as the trust chain verification should be done separately)
    const decoded = decodeJwt({
      headerSchema: z.object({}).passthrough(),
      jwt: rpEntityConfigurationJwt,
      payloadSchema: z
        .object({
          metadata: z
            .object({
              openid_credential_verifier: z.any(),
            })
            .passthrough(),
        })
        .passthrough(),
    });

    const rpMetadata = decoded.payload.metadata?.openid_credential_verifier;

    if (!rpMetadata) {
      throw new ParseAuthorizeRequestError(
        "No openid_credential_verifier metadata found in trust chain",
      );
    }

    // Validate the metadata structure
    // Note: we use a minimal validation here, full validation should be done by the caller
    if (
      !rpMetadata.jwks ||
      !rpMetadata.jwks.keys ||
      !Array.isArray(rpMetadata.jwks.keys)
    ) {
      throw new ParseAuthorizeRequestError(
        "Invalid openid_credential_verifier metadata: missing or invalid jwks",
      );
    }

    return rpMetadata as ItWalletCredentialVerifierMetadata;
  } catch (error) {
    if (error instanceof ParseAuthorizeRequestError) {
      throw error;
    }
    throw new ParseAuthorizeRequestError(
      `Failed to extract RP metadata from trust chain: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function findKeyByKid(jwks: Jwk[], kid: string | undefined): Jwk {
  if (kid) {
    const issuerPublicKey = jwks.find((key: Jwk) => key.kid === kid);

    if (!issuerPublicKey) {
      throw new ParseAuthorizeRequestError(`No key found matching kid: ${kid}`);
    }

    return issuerPublicKey;
  }

  // Fallback: use first key if no kid in header
  if (jwks.length > 0) {
    return jwks[0] as Jwk;
  }

  throw new ParseAuthorizeRequestError("jwks.keys is empty");
}

/**
 * Retrieves the public key for verifying the Request Object JWT signature
 * according to IT Wallet specifications.
 *
 * Priority order:
 * 1. If client_id has x509_hash prefix: use client_metadata.jwks
 * 2. If client_id has openid_federation prefix or no prefix: extract metadata from trust_chain in header
 *
 * @param options - Parse options containing decoded JWT
 * @returns The JWK to use for signature verification
 * @throws {ParseAuthorizeRequestError} When no valid public key can be found
 */
async function getPublicKeyForVerification(options: {
  header: Openid4vpAuthorizationRequestHeader;
  payload: AuthorizationRequestObject;
}): Promise<Jwk> {
  const { header, payload } = options;

  const clientIdPrefix = extractClientIdPrefix(payload.client_id);

  // Priority 1: x509_hash prefix - use client_metadata
  if (clientIdPrefix === ClientIdPrefix.X509_HASH) {
    if (!payload.client_metadata?.jwks?.keys) {
      throw new ParseAuthorizeRequestError(
        "client_id uses x509_hash prefix but client_metadata.jwks is missing",
      );
    }

    return findKeyByKid(payload.client_metadata.jwks.keys, header.kid);
  }

  // Priority 2: openid_federation prefix or no prefix - extract from trust_chain
  // Note: client_metadata MUST be ignored when openid_federation prefix is present
  if (
    clientIdPrefix === ClientIdPrefix.OPENID_FEDERATION ||
    clientIdPrefix === ClientIdPrefix.NONE
  ) {
    if (!header.trust_chain) {
      throw new ParseAuthorizeRequestError(
        "trust_chain is required in JWT header for openid_federation client_id or no prefix",
      );
    }

    const rpMetadata = await extractRpMetadataFromTrustChain(
      header.trust_chain,
    );

    if (!rpMetadata.jwks?.keys) {
      throw new ParseAuthorizeRequestError(
        "No jwks found in RP metadata from trust chain",
      );
    }

    return findKeyByKid(rpMetadata.jwks?.keys, header.kid);
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

/**
 * This method verifies a JWT containing a Request Object and returns its
 * decoded value for further processing.
 *
 * The public key for signature verification is obtained according to IT Wallet specifications:
 * 1. If client_id has x509_hash prefix: use client_metadata.jwks
 * 2. If client_id has openid_federation prefix or no prefix: extract from header.trust_chain
 *
 * @param options {@link ParseAuthorizeRequestOptions}
 * @returns An {@link AuthorizationRequestObject} containing the RP required credentials
 * @throws {@link ValidationError} in case there are errors validating the Request Object structure
 * @throws {@link Oauth2JwtParseError} in case the request object jwt is malformed (e.g missing header, bad encoding)
 * @throws {@link ParseAuthorizeRequestError} in case the JWT signature is invalid or there are unexpected errors
 */
export async function parseAuthorizeRequest(
  options: ParseAuthorizeRequestOptions,
): Promise<AuthorizationRequestObject> {
  try {
    const decoded = decodeJwt({
      headerSchema: zOpenid4vpAuthorizationRequestHeader,
      jwt: options.requestObjectJwt,
      payloadSchema: zOpenid4vpAuthorizationRequestPayload,
    });

    const publicKey = await getPublicKeyForVerification({
      header: decoded.header,
      payload: decoded.payload,
    });

    if (!publicKey.alg) {
      throw new ParseAuthorizeRequestError(
        "Public key must contain an 'alg' field for verification",
      );
    }

    const signer = {
      alg: publicKey.alg,
      method: "jwk" as const,
      publicJwk: publicKey,
    };

    const verificationResult = await options.callbacks.verifyJwt(signer, {
      compact: options.requestObjectJwt,
      header: decoded.header,
      payload: decoded.payload,
    });

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
