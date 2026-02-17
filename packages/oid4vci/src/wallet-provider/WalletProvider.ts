import { CallbackContext, Jwk, JwtSignerX5c } from "@openid4vc/oauth2";
import { addSecondsToDate, dateToSeconds } from "@openid4vc/utils";
import { V1_0, V1_3 } from "@pagopa/io-wallet-oauth2";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";

import { WalletProviderError } from "../errors";
import { WalletAttestationOptions } from "./types";
import { KeyAttestationStatus, KeyStorageLevel } from "./z-key-attestation";

function assertV1_0Options(
  options: WalletAttestationOptions,
): asserts options is V1_0.WalletAttestationOptionsV1_0 {
  if (options.signer.method !== "federation") {
    throw new WalletProviderError(
      `Version mismatch: provider is configured for v1.0 (federation) but received options with signer method "${options.signer.method}"`,
    );
  }
}

function assertV1_3Options(
  options: WalletAttestationOptions,
): asserts options is V1_3.WalletAttestationOptionsV1_3 {
  if (options.signer.method !== "x5c") {
    throw new WalletProviderError(
      `Version mismatch: provider is configured for v1.3 (x5c) but received options with signer method "${options.signer.method}"`,
    );
  }
}

export interface KeyAttestationOptions {
  /**
   * The array of JWKs representing the attested keys.
   */
  attestedKeys: [Jwk, ...Jwk[]];

  callbacks: Pick<CallbackContext, "signJwt">;

  /**
   * Optional URL to the key storage component certification.
   */
  certification?: string;

  /**
   * The optional expiration date for the attestation JWT. If not provided, a default lifetime will be used.
   * @type {Date}
   */
  expiresAt?: Date;

  /**
   * The issuance date of the key attestation. Defaults to the current date and time if not provided.
   * @type {Date}
   */
  issuedAt?: Date;

  issuer: string;

  /**
   * The levels of security for key storage as per ISO 18045 standards.
   * @type {[KeyStorageLevel, ...KeyStorageLevel[]]}
   */
  keyStorage: [KeyStorageLevel, ...KeyStorageLevel[]];

  /**
   * The signer information containing the Key ID and the X.509 certificate chain.
   */
  signer: JwtSignerX5c;

  /**
   * The status information related to the key attestation.
   */
  status: KeyAttestationStatus;

  /**
   * An array of JWTs representing the chain of trust from the federation's trust anchor
   * @type {[string, ...string[]]}
   */
  trustChain?: [string, ...string[]];

  /**
   * The levels of user authentication as per ISO 18045 standards.
   * @type {[KeyStorageLevel, ...KeyStorageLevel[]]}
   */
  userAuthentication: [KeyStorageLevel, ...KeyStorageLevel[]];
}

/**
 * @class WalletProvider
 * @description An implementation of a wallet provider for the OpenID4VCI protocol, tailored for the Italian ecosystem.
 * It handles the creation of wallet attestations required during the credential issuance flow.
 */
export class WalletProvider {
  private specVersion: ItWalletSpecsVersion;

  constructor(options: IoWalletSdkConfig) {
    this.specVersion = options.itWalletSpecsVersion;
  }

  /**
   * Creates a wallet unit attestation.
   *
   * The key attestation is a signed token that describes the attested keys, their storage characteristics,
   * user authentication level, and status, and can include certification and a trust chain as needed.
   *
   * @public
   * @async
   * @param {KeyAttestationOptions} options - The options used to construct and sign the key attestation JWT.
   * @returns {Promise<string>} A promise that resolves to the signed key attestation JWT.
   * @throws {WalletProviderError} Thrown when the JWT cannot be created or signed.
   */
  public async createItKeyAttestationJwt(
    options: KeyAttestationOptions,
  ): Promise<string> {
    const { signJwt } = options.callbacks;

    const now = new Date();
    const issuedAt = options.issuedAt ?? now;
    const expiresAt =
      options.expiresAt ?? addSecondsToDate(now, 3600 * 24 * 360);

    const header = {
      alg: options.signer.alg,
      kid: options.signer.kid,
      typ: "key-attestation+jwt" as const,
      x5c: options.signer.x5c,
      ...(options.trustChain && { trust_chain: options.trustChain }),
    };

    const payload = {
      attested_keys: options.attestedKeys,
      exp: dateToSeconds(expiresAt),
      iat: dateToSeconds(issuedAt),
      iss: options.issuer,
      key_storage: options.keyStorage,
      status: options.status,
      user_authentication: options.userAuthentication,
      ...(options.certification && { certification: options.certification }),
    };

    try {
      const { jwt } = await signJwt(options.signer, {
        header,
        payload,
      });

      return jwt;
    } catch (error) {
      throw new WalletProviderError(
        `Failed to create key attestation JWT: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Creates a wallet attestation JWT according to the configured Italian Wallet specification version.
   *
   * Version Differences:
   * - v1.0: Uses only `trust_chain` in header (federation method)
   * - v1.3: Requires `x5c` in header, optional `trust_chain`, supports `nbf` and `status` claims
   *
   * @public
   * @async
   * @param {WalletAttestationOptions} options - The necessary parameters to build the attestation.
   * @returns {Promise<string>} A promise that resolves to the signed wallet attestation JWT as a string.
   * @throws {WalletProviderError} When dpopJwkPublic.kid is missing
   * @throws {ItWalletSpecsVersionError} When version is not supported
   *
   * @example v1.0 - Basic wallet attestation with trust chain
   * const jwt = await provider.createItWalletAttestationJwt({
   *   callbacks: { signJwt: mySignJwtCallback },
   *   dpopJwkPublic: myJwk,
   *   issuer: "https://wallet-provider.example.com",
   *   signer: {
   *     alg: "ES256",
   *     kid: "provider-key-id",
   *     trustChain: ["trust-anchor-jwt", "intermediate-jwt"]
   *   }
   * });
   *
   * @example v1.3 - Wallet attestation with x5c and optional fields
   * const jwt = await provider.createItWalletAttestationJwt({
   *   callbacks: { signJwt: mySignJwtCallback },
   *   dpopJwkPublic: myJwk,
   *   issuer: "https://wallet-provider.example.com",
   *   signer: {
   *     alg: "ES256",
   *     kid: "provider-key-id",
   *     x5c: ["cert1-base64", "cert2-base64"],
   *     trustChain: ["trust-anchor-jwt"] // Optional in v1.3
   *   },
   *   nbf: new Date('2025-01-01'), // Optional
   *   status: { status_list: { idx: 2, uri: "https://status.example.com" } } // Optional
   * });
   */

  public async createItWalletAttestationJwt(
    options: WalletAttestationOptions,
  ): Promise<string> {
    // Validate that dpopJwkPublic has a kid property
    // This validation is common across all versions
    if (!options.dpopJwkPublic.kid) {
      throw new WalletProviderError("The DPoP JWK must have a 'kid' property");
    }

    if (this.specVersion === ItWalletSpecsVersion.V1_0) {
      assertV1_0Options(options);
      return V1_0.createWalletAttestationJwt({
        authenticatorAssuranceLevel: options.authenticatorAssuranceLevel,
        callbacks: options.callbacks,
        dpopJwkPublic: options.dpopJwkPublic,
        expiresAt: options.expiresAt,
        issuer: options.issuer,
        signer: options.signer,
        walletLink: options.walletLink,
        walletName: options.walletName,
      });
    }

    if (this.specVersion === ItWalletSpecsVersion.V1_3) {
      assertV1_3Options(options);
      return V1_3.createWalletAttestationJwt({
        callbacks: options.callbacks,
        dpopJwkPublic: options.dpopJwkPublic,
        expiresAt: options.expiresAt,
        issuer: options.issuer,
        nbf: options.nbf,
        signer: options.signer,
        status: options.status,
        walletLink: options.walletLink,
        walletName: options.walletName,
      });
    }

    throw new ItWalletSpecsVersionError(
      "createItWalletAttestationJwt",
      this.specVersion,
      [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
    );
  }
}
