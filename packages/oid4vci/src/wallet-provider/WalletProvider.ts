import { Openid4vciWalletProvider } from "@openid4vc/openid4vci";
import {
  ItWalletSpecsVersion,
  ItWalletSpecsVersionError,
} from "@pagopa/io-wallet-utils";

import type { WalletAttestationOptions } from "./types";

import { WalletProviderError } from "../errors";
import * as V1_0 from "./v1.0";
import * as V1_3 from "./v1.3";

/**
 * Type guard to check if options are for v1.0
 */
function isV1_0Options(
  options: WalletAttestationOptions,
): options is V1_0.WalletAttestationOptionsV1_0 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_0;
}

/**
 * Type guard to check if options are for v1.3
 */
function isV1_3Options(
  options: WalletAttestationOptions,
): options is V1_3.WalletAttestationOptionsV1_3 {
  return options.config.itWalletSpecsVersion === ItWalletSpecsVersion.V1_3;
}

/**
 * @class WalletProvider
 * @extends Openid4vciWalletProvider
 * @description An implementation of a wallet provider for the OpenID4VCI protocol, tailored for the Italian ecosystem.
 * It handles the creation of wallet attestations required during the credential issuance flow.
 */
export class WalletProvider extends Openid4vciWalletProvider {
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
   *   config: { itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 },
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
   *   config: { itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 },
   *   dpopJwkPublic: myJwk,
   *   issuer: "https://wallet-provider.example.com",
   *   signer: {
   *     alg: "ES256",
   *     kid: "provider-key-id",
   *     x5c: ["cert1-base64", "cert2-base64"],
   *     trustChain: ["trust-anchor-jwt"] // Optional in v1.3
   *   },
   *   nbf: new Date('2025-01-01'), // Optional
   *   status: { status_list: { idx: "0", uri: "https://status.example.com" } } // Optional
   * });
   */
  // Function overload for v1.0

  public async createItWalletAttestationJwt(
    options: V1_0.WalletAttestationOptionsV1_0,
  ): Promise<string>;

  // Function overload for v1.3

  public async createItWalletAttestationJwt(
    options: V1_3.WalletAttestationOptionsV1_3,
  ): Promise<string>;

  // Implementation signature (not callable by users)
  public async createItWalletAttestationJwt(
    options: WalletAttestationOptions,
  ): Promise<string> {
    if (!options.config) {
      throw new WalletProviderError(
        "config parameter is required with itWalletSpecsVersion",
      );
    }

    // Store version for error reporting
    const version = options.config.itWalletSpecsVersion;

    // Validate that dpopJwkPublic has a kid property
    // This validation is common across all versions
    if (!options.dpopJwkPublic.kid) {
      throw new WalletProviderError("The DPoP JWK must have a 'kid' property");
    }

    if (isV1_0Options(options)) {
      // For v1.0: use trust_chain only
      return V1_0.createWalletAttestationJwt({
        callbacks: options.callbacks,
        config: options.config,
        dpopJwkPublic: options.dpopJwkPublic,
        expiresAt: options.expiresAt,
        issuer: options.issuer,
        signer: options.signer,
        walletLink: options.walletLink,
        walletName: options.walletName,
      });
    }

    if (isV1_3Options(options)) {
      // For v1.3: use x5c (required) and optional trust_chain, nbf, status
      return V1_3.createWalletAttestationJwt({
        callbacks: options.callbacks,
        config: options.config,
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
      version,
      [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
    );
  }
}
