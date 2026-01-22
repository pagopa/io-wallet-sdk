/**
 * Supported versions of the Italian Wallet technical specifications
 */
export enum ItWalletSpecsVersion {
  V1_0 = "V1_0",
  V1_3 = "V1_3",
}

/**
 * Configuration options for the IO Wallet SDK
 */
export interface IoWalletSdkConfigOptions {
  /**
   * The version of the Italian Wallet specification to use.
   * REQUIRED - must be explicitly set by the user.
   *
   * Version differences:
   * - V1_0: Uses singular `proof` object with explicit `proof_type` field
   * - V1_3: Uses plural `proofs` object with JWT array and requires key attestation
   *
   * @example
   * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
   */
  itWalletSpecsVersion: ItWalletSpecsVersion;
}

/**
 * Configuration class for the IO Wallet SDK
 *
 * This class manages the version of the Italian Wallet technical specifications
 * to use throughout the SDK. The version determines the format of credential
 * requests and responses.
 *
 * @example Basic usage
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 });
 * console.log(config.itWalletSpecsVersion); // ItWalletSpecsVersion.V1_0
 *
 * @example Type guard usage
 * if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
 *   // TypeScript narrows config.itWalletSpecsVersion to ItWalletSpecsVersion.V1_3
 * }
 */
export class IoWalletSdkConfig {
  public readonly itWalletSpecsVersion: ItWalletSpecsVersion;

  constructor(options: IoWalletSdkConfigOptions) {
    this.itWalletSpecsVersion = options.itWalletSpecsVersion;
  }

  /**
   * Type guard for version checking
   *
   * @param version - The version to check against
   * @returns True if the config's version matches the provided version
   *
   * @internal
   */
  isVersion<V extends ItWalletSpecsVersion>(
    version: V,
  ): this is { itWalletSpecsVersion: V } & IoWalletSdkConfig {
    return this.itWalletSpecsVersion === version;
  }
}
