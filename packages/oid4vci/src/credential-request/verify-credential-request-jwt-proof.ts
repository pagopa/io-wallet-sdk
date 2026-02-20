import {
  CallbackContext,
  HashAlgorithm,
  Oauth2JwtParseError,
  calculateJwkThumbprint,
  jwtSignerFromJwt,
} from "@openid4vc/oauth2";
import { Jwk, decodeJwt, verifyJwt } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
  ValidationError,
} from "@pagopa/io-wallet-utils";

import { VerifyCredentialRequestJwtProofError } from "../errors";
import {
  VerifyKeyAttestationJwtResult,
  verifyKeyAttestationJwt,
} from "./verify-key-attestation-jwt";
import {
  ProofJwtHeaderV1_0,
  ProofJwtHeaderV1_3,
  ProofJwtPayload,
  zProofJwtHeaderV1_0,
  zProofJwtHeaderV1_3,
  zProofJwtPayload,
} from "./z-proof-jwt";

/**
 * Options for verifying a credential request JWT proof.
 */
export interface VerifyCredentialRequestJwtProofOptions {
  /**
   * Callbacks required for JWT signature verification and JWK thumbprint hashing.
   */
  callbacks: Pick<CallbackContext, "hash" | "verifyJwt">;
  /**
   * The client id of the wallet requesting the credential.
   * If provided, it will be matched against the `iss` claim.
   */
  clientId?: string;
  /**
   * SDK configuration that determines the IT-Wallet specification version.
   * Controls which header schema is used and whether key attestation is verified.
   */
  config: IoWalletSdkConfig;
  /**
   * The credential issuer identifier. Matched against the `aud` claim.
   */
  credentialIssuer: string;
  /**
   * Expected nonce value. Should be a `c_nonce` previously shared with the wallet
   * via the Nonce Endpoint.
   */
  expectedNonce?: string;
  /**
   * The compact JWT proof to verify.
   */
  jwt: string;
  /**
   * Date at which the nonce expires. If the current time exceeds this value,
   * verification fails before signature checking.
   */
  nonceExpiresAt?: Date;
  /**
   * Current time override. If not provided, `Date.now()` is used.
   */
  now?: Date;
}

interface IsJwkInSetOptions {
  callbacks: Pick<CallbackContext, "hash">;
  jwk: Jwk;
  jwks: Jwk[];
}

async function isJwkInSet(options: IsJwkInSetOptions): Promise<boolean> {
  const targetThumbprint = await calculateJwkThumbprint({
    hashAlgorithm: HashAlgorithm.Sha256,
    hashCallback: options.callbacks.hash,
    jwk: options.jwk,
  });

  const thumbprints = await Promise.all(
    options.jwks.map((jwk) =>
      calculateJwkThumbprint({
        hashAlgorithm: HashAlgorithm.Sha256,
        hashCallback: options.callbacks.hash,
        jwk,
      }),
    ),
  );

  return thumbprints.includes(targetThumbprint);
}

/**
 * Verification result for IT-Wallet specification v1.0.
 * Does not include key attestation.
 */
export interface VerifyCredentialRequestJwtProofResultV1_0 {
  header: ProofJwtHeaderV1_0;
  payload: ProofJwtPayload;
  signer: Awaited<ReturnType<typeof verifyJwt>>["signer"];
}

/**
 * Verification result for IT-Wallet specification v1.3.
 * Includes the verified key attestation.
 */
export interface VerifyCredentialRequestJwtProofResultV1_3 {
  header: ProofJwtHeaderV1_3;
  keyAttestation: VerifyKeyAttestationJwtResult;
  payload: ProofJwtPayload;
  signer: Awaited<ReturnType<typeof verifyJwt>>["signer"];
}

export type VerifyCredentialRequestJwtProofResult =
  | VerifyCredentialRequestJwtProofResultV1_0
  | VerifyCredentialRequestJwtProofResultV1_3;

/**
 * Verifies a credential request JWT proof according to the configured IT-Wallet specification version.
 *
 * Performs the following checks:
 * 1. Validates nonce expiry (if `nonceExpiresAt` is provided)
 * 2. Decodes and validates the JWT header and payload using version-specific schemas
 * 3. Verifies the JWT signature via the `verifyJwt` callback
 * 4. (v1.3 only) Verifies the `key_attestation` JWT and checks that the proof signer key
 *    is present in the key attestation's `attested_keys`
 *
 * @param options - Verification options and callbacks.
 * @returns Decoded header, payload, signer, and (v1.3) key attestation result.
 * @throws {VerifyCredentialRequestJwtProofError} If nonce is expired, signature is invalid,
 *   or the signer key is not in the attested keys.
 * @throws {ItWalletSpecsVersionError} If the configured specification version is unsupported.
 * @throws {ValidationError} If JWT header or payload schema validation fails.
 * @throws {Oauth2JwtParseError} If JWT decoding fails.
 */
export async function verifyCredentialRequestJwtProof(
  options: VerifyCredentialRequestJwtProofOptions,
): Promise<VerifyCredentialRequestJwtProofResult> {
  const { config } = options;

  try {
    const now = options.now?.getTime() ?? Date.now();

    if (options.nonceExpiresAt && now > options.nonceExpiresAt.getTime()) {
      throw new VerifyCredentialRequestJwtProofError(
        "Nonce used for credential request proof expired",
      );
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_0)) {
      const { header, payload } = decodeJwt({
        headerSchema: zProofJwtHeaderV1_0,
        jwt: options.jwt,
        payloadSchema: zProofJwtPayload,
      });

      const { signer } = await verifyJwt({
        compact: options.jwt,
        errorMessage: "Error verifying credential request proof jwt.",
        expectedAudience: options.credentialIssuer,
        expectedIssuer: options.clientId,
        expectedNonce: options.expectedNonce,
        header,
        now: options.now,
        payload,
        signer: jwtSignerFromJwt({ header, payload }),
        verifyJwtCallback: options.callbacks.verifyJwt,
      });

      return {
        header,
        payload,
        signer,
      };
    }

    if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
      const { header, payload } = decodeJwt({
        headerSchema: zProofJwtHeaderV1_3,
        jwt: options.jwt,
        payloadSchema: zProofJwtPayload,
      });

      const { signer } = await verifyJwt({
        compact: options.jwt,
        errorMessage: "Error verifying credential request proof jwt.",
        expectedAudience: options.credentialIssuer,
        expectedIssuer: options.clientId,
        expectedNonce: options.expectedNonce,
        header,
        now: options.now,
        payload,
        signer: jwtSignerFromJwt({ header, payload }),
        verifyJwtCallback: options.callbacks.verifyJwt,
      });

      const keyAttestationResult = await verifyKeyAttestationJwt({
        callbacks: options.callbacks,
        keyAttestationJwt: header.key_attestation,
        now: options.now,
      });

      const isSignedWithAttestedKey = await isJwkInSet({
        callbacks: options.callbacks,
        jwk: signer.publicJwk,
        jwks: keyAttestationResult.payload.attested_keys,
      });

      if (!isSignedWithAttestedKey) {
        throw new VerifyCredentialRequestJwtProofError(
          "Credential request jwt proof is not signed with a key in the 'key_attestation' jwt payload 'attested_keys'",
        );
      }

      return {
        header,
        keyAttestation: keyAttestationResult,
        payload,
        signer,
      };
    }

    throw new ItWalletSpecsVersionError(
      "verifyCredentialRequestJwtProof",
      config.itWalletSpecsVersion,
      [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
    );
  } catch (error) {
    if (
      error instanceof VerifyCredentialRequestJwtProofError ||
      error instanceof ItWalletSpecsVersionError ||
      error instanceof ValidationError ||
      error instanceof Oauth2JwtParseError
    ) {
      throw error;
    }

    throw new VerifyCredentialRequestJwtProofError(
      `Unexpected error during credential request proof verification: ${
        error instanceof Error ? error.message : String(error)
      }`,
      error,
    );
  }
}
