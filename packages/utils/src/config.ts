/**
 * Supported versions of the Italian Wallet technical specifications
 */
export type ItWalletSpecsVersion = "1.0.2" | "1.3.3";

/**
 * Configuration options for the IO Wallet SDK
 */
export interface IoWalletSdkConfigOptions {
  /**
   * The version of the Italian Wallet specification to use.
   * REQUIRED - must be explicitly set by the user.
   *
   * Version differences:
   * - v1.0.2: Uses singular `proof` object with explicit `proof_type` field
   * - v1.3.3: Uses plural `proofs` object with JWT array and requires key attestation
   *
   * @example
   * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: '1.3.3' });
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
 * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: '1.0.2' });
 * console.log(config.itWalletSpecsVersion); // '1.0.2'
 *
 * @example Type guard usage
 * if (config.isVersion('1.3.3')) {
 *   // TypeScript narrows config.itWalletSpecsVersion to '1.3.3'
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
