import {
  Oauth2JwtParseError,
  decodeJwt,
  extractDpopJwtFromHeaders,
} from "@pagopa/io-wallet-oauth2";
import {
  FetchHeaders,
  HEADERS,
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  ValidationError,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import {
  CredentialAuthorizationHeaderError,
  MissingDpopProofError as CredentialDpopProofError,
  ParseCredentialRequestError,
} from "../errors";
import {
  CredentialRequestV1_0,
  zCredentialRequestV1_0,
} from "./v1.0/z-credential";
import {
  CredentialRequestV1_3,
  zCredentialRequestV1_3,
} from "./v1.3/z-credential";
import {
  ProofJwtHeader,
  ProofJwtPayload,
  zProofJwtHeaderV1_0,
  zProofJwtHeaderV1_3,
  zProofJwtPayload,
} from "./z-proof-jwt";

type GrantType = "authorization_code" | "pre-authorized_code";

/**
 * A normalized proof extracted from the credential request.
 * The proof JWT is decoded and validated, but its signature is not verified.
 */
export interface ParsedCredentialProof {
  /** Parsed proof JWT header. */
  header: ProofJwtHeader;
  /** Original compact JWT proof. */
  jwt: string;
  /** Parsed proof JWT payload. */
  payload: ProofJwtPayload;
  /** Normalized proof type. */
  proofType: "jwt";
}

/**
 * Optional expected values used for semantic validation during parsing.
 */
export interface ParseCredentialRequestExpectedValues {
  /** Expected `aud` claim inside the proof JWT payload. */
  audience?: string;
  /** Expected credential configuration identifier in the request body. */
  credential_configuration_id?: string;
  /** Expected credential identifier in the request body. */
  credential_identifier?: string;
  /** Expected `iss` claim inside the proof JWT payload. */
  issuer?: string;
  /** Expected `nonce` claim inside the proof JWT payload. */
  nonce?: string;
}

/**
 * Input options for parsing a credential request.
 */
export interface ParseCredentialRequestOptions {
  /** SDK config used to route parsing logic by IT-Wallet specification version. */
  config: IoWalletSdkConfig;
  /** Credential request payload to validate and parse. */
  credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
  /** Optional expected values for semantic checks. */
  expected?: ParseCredentialRequestExpectedValues;
  /** Grant type used to validate `iss` requirements in proof JWT payloads. */
  grantType?: GrantType;
  /** HTTP headers of the credential request, used to extract the DPoP proof. */
  headers: FetchHeaders;
  /** Whether the request is expected to be part of deferred issuance flow. */
  isDeferredFlow?: boolean;
}

/**
 * Parsed and normalized credential request.
 */
export interface ParsedCredentialRequest {
  /** Access token extracted from the Authorization header. */
  accessToken: string;
  /** Normalized credential selector values from the request body. */
  credential: {
    credential_configuration_id?: string;
    credential_identifier?: string;
  };
  /** Version-specific validated credential request. */
  credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
  /** DPoP proof JWT extracted from the request headers. */
  dpopProof: string;
  /** Normalized list of parsed proof JWTs. */
  proofs: ParsedCredentialProof[];
  /** Transaction metadata derived from flow context and request payload. */
  transaction: {
    isDeferredFlow: boolean;
    transaction_id?: string;
  };
}

/**
 * Validates request body identifiers against optionally provided expected values.
 */
function validateExpectedValues(
  credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3,
  expected?: ParseCredentialRequestExpectedValues,
): void {
  if (!expected) {
    return;
  }

  if (
    expected.credential_identifier &&
    credentialRequest.credential_identifier !== expected.credential_identifier
  ) {
    throw new ValidationError(
      "credential_identifier does not match expected value",
    );
  }

  if (
    expected.credential_configuration_id &&
    credentialRequest.credential_configuration_id !==
      expected.credential_configuration_id
  ) {
    throw new ValidationError(
      "credential_configuration_id does not match expected value",
    );
  }
}

/**
 * Validates that transaction_id presence matches deferred/immediate flow context.
 */
function validateTransactionContext(options: {
  credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
  isDeferredFlow: boolean;
}): void {
  const { credentialRequest, isDeferredFlow } = options;

  if (isDeferredFlow && !credentialRequest.transaction_id) {
    throw new ValidationError(
      "transaction_id is required for deferred credential issuance",
    );
  }

  if (!isDeferredFlow && credentialRequest.transaction_id) {
    throw new ValidationError(
      "transaction_id must not be present in immediate credential issuance flow",
    );
  }
}

/**
 * Decodes and validates a single proof JWT, then applies semantic claim checks.
 */
function parseProofJwt(options: {
  expected?: ParseCredentialRequestExpectedValues;
  grantType: GrantType;
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 | ItWalletSpecsVersion.V1_3;
  jwt: string;
}): ParsedCredentialProof {
  const decoded = decodeJwt({
    errorMessagePrefix: "Error decoding credential request proof JWT:",
    jwt: options.jwt,
  });
  const headerValidation =
    options.itWalletSpecsVersion === ItWalletSpecsVersion.V1_3
      ? zProofJwtHeaderV1_3.safeParse(decoded.header)
      : zProofJwtHeaderV1_0.safeParse(decoded.header);

  if (!headerValidation.success) {
    throw new ValidationError(
      "Credential proof JWT header is invalid or missing required claims",
    );
  }

  const payloadValidation = zProofJwtPayload.safeParse(decoded.payload);
  if (!payloadValidation.success) {
    throw new ValidationError(
      "Credential proof JWT payload is invalid or missing required claims",
    );
  }

  const payload = payloadValidation.data;

  if (options.grantType === "authorization_code" && !payload.iss) {
    throw new ValidationError(
      "Credential proof JWT payload must include iss for authorization_code grant",
    );
  }

  if (options.expected?.audience && payload.aud !== options.expected.audience) {
    throw new ValidationError(
      "Credential proof JWT aud does not match expected audience",
    );
  }

  if (options.expected?.nonce && payload.nonce !== options.expected.nonce) {
    throw new ValidationError(
      "Credential proof JWT nonce does not match expected nonce",
    );
  }

  if (
    options.expected?.issuer &&
    payload.iss &&
    payload.iss !== options.expected.issuer
  ) {
    throw new ValidationError(
      "Credential proof JWT iss does not match expected issuer",
    );
  }

  if (
    options.grantType === "authorization_code" &&
    options.expected?.issuer &&
    !payload.iss
  ) {
    throw new ValidationError(
      "Credential proof JWT payload is missing expected issuer (iss)",
    );
  }

  return {
    header: headerValidation.data,
    jwt: options.jwt,
    payload,
    proofType: "jwt",
  };
}

/**
 * Converts version-specific proof containers (`proof` or `proofs.jwt[]`) into a normalized array.
 */
function normalizeProofs(options: {
  credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
  expected?: ParseCredentialRequestExpectedValues;
  grantType: GrantType;
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 | ItWalletSpecsVersion.V1_3;
}): ParsedCredentialProof[] {
  if ("proof" in options.credentialRequest) {
    return [
      parseProofJwt({
        expected: options.expected,
        grantType: options.grantType,
        itWalletSpecsVersion: options.itWalletSpecsVersion,
        jwt: options.credentialRequest.proof.jwt,
      }),
    ];
  }

  return options.credentialRequest.proofs.jwt.map((jwt) =>
    parseProofJwt({
      expected: options.expected,
      grantType: options.grantType,
      itWalletSpecsVersion: options.itWalletSpecsVersion,
      jwt,
    }),
  );
}

/**
 * Builds the normalized parse result shared by v1.0 and v1.3 flows.
 */
function toResult<
  TRequest extends CredentialRequestV1_0 | CredentialRequestV1_3,
>(options: {
  accessToken: string;
  credentialRequest: TRequest;
  dpopProof: string;
  expected?: ParseCredentialRequestExpectedValues;
  grantType: GrantType;
  isDeferredFlow: boolean;
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 | ItWalletSpecsVersion.V1_3;
}): ParsedCredentialRequest {
  validateExpectedValues(options.credentialRequest, options.expected);
  validateTransactionContext({
    credentialRequest: options.credentialRequest,
    isDeferredFlow: options.isDeferredFlow,
  });

  const proofs = normalizeProofs({
    credentialRequest: options.credentialRequest,
    expected: options.expected,
    grantType: options.grantType,
    itWalletSpecsVersion: options.itWalletSpecsVersion,
  });

  return {
    accessToken: options.accessToken,
    credential: {
      credential_configuration_id:
        options.credentialRequest.credential_configuration_id,
      credential_identifier: options.credentialRequest.credential_identifier,
    },
    credentialRequest: options.credentialRequest,
    dpopProof: options.dpopProof,
    proofs,
    transaction: {
      isDeferredFlow: options.isDeferredFlow,
      transaction_id: options.credentialRequest.transaction_id,
    },
  };
}

/**
 * Extracts and validates the DPoP-bound access token from the Authorization header.
 */
function parseAuthorizationHeader(headers: FetchHeaders): string {
  const authorizationHeader = headers.get(HEADERS.AUTHORIZATION)?.trim();

  if (!authorizationHeader) {
    throw new CredentialAuthorizationHeaderError(
      "Credential request is missing required 'Authorization' header with DPoP scheme",
    );
  }

  const [scheme, token, ...rest] = authorizationHeader.split(/\s+/);

  // Per RFC 9110 authentication schemes are case-insensitive
  if (rest.length > 0 || scheme?.toLowerCase() !== "dpop" || !token) {
    throw new CredentialAuthorizationHeaderError(
      "Credential request contains an invalid 'Authorization' header. Expected format: 'Authorization: DPoP <access_token>'",
    );
  }

  return token;
}

/**
 * Extracts and validates the DPoP proof JWT from the request headers.
 */
function parseDpopProof(headers: FetchHeaders): string {
  const extracted = extractDpopJwtFromHeaders(headers);

  if (!extracted.valid) {
    throw new CredentialDpopProofError(
      "Credential request contains a 'DPoP' header, but the value is not a valid JWT format",
    );
  }

  if (!extracted.dpopJwt) {
    throw new CredentialDpopProofError(
      "Credential request contains a 'DPoP' header, but the value is missing or empty",
    );
  }

  return extracted.dpopJwt;
}

/**
 * Parses and validates a credential request for the configured IT-Wallet version.
 *
 * Performs the following validations in order:
 * 1. **Authorization header** — asserts the `Authorization` HTTP header is present
 *    and uses the `DPoP` scheme with a non-empty access token. The extracted token
 *    is returned as `accessToken` for subsequent verification by the caller.
 * 2. **DPoP proof header** — asserts the `DPoP` HTTP header is present and contains a
 *    compact JWT. The extracted JWT is returned as `dpopProof` for subsequent
 *    cryptographic verification by the caller (e.g. via `verifyTokenDPoP`).
 * 3. **Request body schema** — validates the body against the v1.0 or v1.3 schema.
 * 4. **Semantic checks** — verifies optional expected values (`audience`, `nonce`,
 *    `issuer`, `credential_identifier`, `credential_configuration_id`).
 * 5. **Transaction context** — enforces `transaction_id` presence/absence rules
 *    for deferred vs. immediate issuance flows.
 * 6. **Proof JWT structure** — decodes each proof JWT and validates its header and
 *    payload claims, including `iss` requirements for the `authorization_code` grant.
 *    For v1.3, asserts the `key_attestation` header claim is present and non-empty.
 *
 * This function does not perform cryptographic signature verification on proof JWTs
 * or the DPoP proof. Both must be verified separately after parsing.
 * For DPoP proofs, the caller can use the `verifyTokenDPoP` function exported by io-wallet-oauth2.
 *
 * @param options - Parsing options and validation context.
 * @returns Normalized parsed credential request including the extracted `accessToken` and `dpopProof`.
 * @throws {CredentialAuthorizationHeaderError} If the `Authorization` header is absent or invalid.
 * @throws {CredentialDpopProofError} If the `DPoP` header is absent or not a valid compact JWT.
 * @throws {ValidationError} If request body schema or semantic checks fail.
 * @throws {Oauth2JwtParseError} If a proof JWT cannot be decoded.
 * @throws {ItWalletSpecsVersionError} If the configured specification version is unsupported.
 * @throws {ParseCredentialRequestError} For unexpected parsing failures.
 */
export function parseCredentialRequest(
  options: ParseCredentialRequestOptions,
): ParsedCredentialRequest {
  const grantType = options.grantType ?? "authorization_code";
  const isDeferredFlow = options.isDeferredFlow ?? false;
  const { config } = options;

  try {
    const accessToken = parseAuthorizationHeader(options.headers);
    const dpopProof = parseDpopProof(options.headers);

    if (options.config.isVersion(ItWalletSpecsVersion.V1_0)) {
      const credentialRequest = parseWithErrorHandling(
        zCredentialRequestV1_0,
        options.credentialRequest,
        "Invalid credential request format for ItWalletSpecsVersion 1.0",
      );

      return toResult({
        accessToken,
        credentialRequest,
        dpopProof,
        expected: options.expected,
        grantType,
        isDeferredFlow,
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
      });
    }

    if (options.config.isVersion(ItWalletSpecsVersion.V1_3)) {
      const credentialRequest = parseWithErrorHandling(
        zCredentialRequestV1_3,
        options.credentialRequest,
        "Invalid credential request format for ItWalletSpecsVersion 1.3",
      );

      return toResult({
        accessToken,
        credentialRequest,
        dpopProof,
        expected: options.expected,
        grantType,
        isDeferredFlow,
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
      });
    }

    throw new ItWalletSpecsVersionError(
      "parseCredentialRequest",
      config.itWalletSpecsVersion,
      [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
    );
  } catch (error) {
    if (
      error instanceof ItWalletSpecsVersionError ||
      error instanceof Oauth2JwtParseError ||
      error instanceof ValidationError ||
      error instanceof CredentialAuthorizationHeaderError ||
      error instanceof CredentialDpopProofError
    ) {
      throw error;
    }

    throw new ParseCredentialRequestError(
      `Unexpected error during credential request parsing: ${
        error instanceof Error ? error.message : String(error)
      }`,
      error,
    );
  }
}
