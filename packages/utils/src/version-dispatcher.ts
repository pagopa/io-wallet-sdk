import { ItWalletSpecsVersion } from "./config";
import { ItWalletSpecsVersionError } from "./errors/errors";

export interface VersionedOptions {
  config: { itWalletSpecsVersion: ItWalletSpecsVersion };
}

/**
 * Creates a version-aware dispatcher that routes a function call
 * based on options.config.itWalletSpecsVersion.
 *
 * Throws ItWalletSpecsVersionError for any unregistered version.
 *
 * @param featureName - Used in the error message when version is unsupported
 * @param handlers    - Map of version → handler function
 */
export function createVersionDispatcher<
  TOptions extends VersionedOptions,
  TResult,
>(
  featureName: string,
  handlers: Partial<
    Record<ItWalletSpecsVersion, (options: TOptions) => TResult>
  >,
): (options: TOptions) => TResult {
  const supportedVersions = Object.keys(handlers) as ItWalletSpecsVersion[];

  return (options: TOptions): TResult => {
    const version = options.config.itWalletSpecsVersion;

    const handler = (handlers as Record<string, (o: TOptions) => TResult>)[
      version
    ];

    if (handler) {
      return handler(options);
    }

    throw new ItWalletSpecsVersionError(
      featureName,
      version,
      supportedVersions,
    );
  };
}

/**
 * Dispatches by a bare version value (no options object needed).
 *
 * @param featureName - Used in the error message when version is unsupported
 * @param version     - The version to dispatch on
 * @param handlers    - Map of version → zero-argument handler function
 */
export function dispatchByVersion<TResult>(
  featureName: string,
  version: ItWalletSpecsVersion,
  handlers: Partial<Record<ItWalletSpecsVersion, () => TResult>>,
): TResult {
  const handler = handlers[version];
  if (handler) return handler();
  throw new ItWalletSpecsVersionError(
    featureName,
    version,
    Object.keys(handlers) as ItWalletSpecsVersion[],
  );
}
