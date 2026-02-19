import { Oauth2JwtParseError, decodeJwt } from "@openid4vc/oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  ValidationError,
  parseWithErrorHandling,
} from "@pagopa/io-wallet-utils";

import { ParseCredentialRequestError } from "../errors";
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
  zProofJwtHeader,
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
  /** Whether the request is expected to be part of deferred issuance flow. */
  isDeferredFlow?: boolean;
}

/**
 * Parsed and normalized credential request.
 */
export interface ParsedCredentialRequest {
  /** Normalized credential selector values from the request body. */
  credential: {
    credential_configuration_id?: string;
    credential_identifier?: string;
  };
  /** Version-specific validated credential request. */
  credentialRequest: CredentialRequestV1_0 | CredentialRequestV1_3;
  /** Normalized list of parsed proof JWTs. */
  proofs: ParsedCredentialProof[];
  /** Transaction metadata derived from flow context and request payload. */
  transaction: {
    isDeferredFlow: boolean;
    transaction_id?: string;
  };
}

function isV1_0Options(options: ParseCredentialRequestOptions): boolean {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_0;
}

function isV1_3Options(options: ParseCredentialRequestOptions): boolean {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_3;
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
  jwt: string;
}): ParsedCredentialProof {
  const decoded = decodeJwt({ jwt: options.jwt });
  const headerValidation = zProofJwtHeader.safeParse(decoded.header);
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
}): ParsedCredentialProof[] {
  if ("proof" in options.credentialRequest) {
    return [
      parseProofJwt({
        expected: options.expected,
        grantType: options.grantType,
        jwt: options.credentialRequest.proof.jwt,
      }),
    ];
  }

  return options.credentialRequest.proofs.jwt.map((jwt) =>
    parseProofJwt({
      expected: options.expected,
      grantType: options.grantType,
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
  credentialRequest: TRequest;
  expected?: ParseCredentialRequestExpectedValues;
  grantType: GrantType;
  isDeferredFlow: boolean;
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
  });

  return {
    credential: {
      credential_configuration_id:
        options.credentialRequest.credential_configuration_id,
      credential_identifier: options.credentialRequest.credential_identifier,
    },
    credentialRequest: options.credentialRequest,
    proofs,
    transaction: {
      isDeferredFlow: options.isDeferredFlow,
      transaction_id: options.credentialRequest.transaction_id,
    },
  };
}

/**
 * Parses and validates a credential request for the configured IT-Wallet version.
 *
 * It validates the request body schema (v1.0 or v1.3), enforces semantic checks
 * (expected values, deferred flow rules, grant-type claim constraints), and
 * returns normalized decoded proof data for issuer-side processing.
 *
 * This function does not perform cryptographic signature verification on proof JWTs.
 *
 * @param options - Parsing options and validation context.
 * @returns Normalized parsed credential request.
 * @throws {ItWalletSpecsVersionError} If the configured specification version is unsupported.
 * @throws {ValidationError} If request structure or semantic checks fail.
 * @throws {Oauth2JwtParseError} If proof JWT decoding fails.
 * @throws {ParseCredentialRequestError} For unexpected parsing failures.
 */
export function parseCredentialRequest(
  options: ParseCredentialRequestOptions,
): ParsedCredentialRequest {
  const grantType = options.grantType ?? "authorization_code";
  const isDeferredFlow = options.isDeferredFlow ?? false;
  const { config } = options;

  try {
    if (isV1_0Options(options)) {
      const credentialRequest = parseWithErrorHandling(
        zCredentialRequestV1_0,
        options.credentialRequest,
        "Invalid credential request format for ItWalletSpecsVersion 1.0",
      );

      return toResult({
        credentialRequest,
        expected: options.expected,
        grantType,
        isDeferredFlow,
      });
    }

    if (isV1_3Options(options)) {
      const credentialRequest = parseWithErrorHandling(
        zCredentialRequestV1_3,
        options.credentialRequest,
        "Invalid credential request format for ItWalletSpecsVersion 1.3",
      );

      return toResult({
        credentialRequest,
        expected: options.expected,
        grantType,
        isDeferredFlow,
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
      error instanceof ValidationError
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
