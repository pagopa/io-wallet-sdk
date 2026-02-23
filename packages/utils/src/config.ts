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
export interface IoWalletSdkConfigOptions<
  V extends ItWalletSpecsVersion = ItWalletSpecsVersion,
> {
  /**
   * The version of the Italian Wallet specification to use.
   * REQUIRED - must be explicitly set by the user.
   *
   * @example
   * const config = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 });
   */
  itWalletSpecsVersion: V;
}

interface WithConfig {
  config: IoWalletSdkConfig;
}

type WithVersionedConfig<
  T extends WithConfig,
  V extends ItWalletSpecsVersion,
> = {
  config: IoWalletSdkConfig<V>;
} & T;

/**
 * Type guard to check if the provided options have a specific config version
 *
 * @param options - The options object containing the config to check
 * @param version - The version to check against
 * @returns True if the options' config version matches the provided version
 *
 * @internal
 */
export function hasConfigVersion<
  T extends WithConfig,
  V extends ItWalletSpecsVersion,
>(options: T, version: V): options is WithVersionedConfig<T, V> {
  return options.config.itWalletSpecsVersion === version;
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
export class IoWalletSdkConfig<
  V extends ItWalletSpecsVersion = ItWalletSpecsVersion,
> {
  public readonly itWalletSpecsVersion: V;

  constructor(options: IoWalletSdkConfigOptions<V>) {
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
  isVersion<W extends ItWalletSpecsVersion>(
    version: W,
  ): this is IoWalletSdkConfig<W> {
    const currentVersion: ItWalletSpecsVersion = this.itWalletSpecsVersion;
    return currentVersion === version;
  }
}
