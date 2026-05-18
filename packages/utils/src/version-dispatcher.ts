import { ItWalletSpecsVersion } from "./config";
import { ItWalletSpecsVersionError } from "./errors/errors";

export interface VersionedOptions {
  config: { itWalletSpecsVersion: ItWalletSpecsVersion };
}

/**
 * Creates a version-aware dispatcher that routes a function call
 * based on options.config.itWalletSpecsVersion.
 *
 * All versions declared in `ItWalletSpecsVersion` must be provided
 * (`Required` contract). Adding a new spec version therefore requires
 * updating every `createVersionDispatcher` call site. This is an
 * intentional trade-off: compile-time exhaustiveness is preferred over
 * sparse-map flexibility.
 *
 * @param handlers    - Map of version → handler function
 * @returns Dispatcher function that invokes the handler for `options.config.itWalletSpecsVersion`.
 * @throws {ItWalletSpecsVersionError} If no handler is registered for the configured version.
 */
export function createVersionDispatcher<
  TOptions extends VersionedOptions,
  TResult,
>(
  handlers: Required<
    Record<ItWalletSpecsVersion, (options: TOptions) => TResult>
  >,
): (options: TOptions) => TResult {
  return (options: TOptions): TResult => {
    const version = options.config.itWalletSpecsVersion;
    const handler = handlers[version];
    if (typeof handler !== "function") {
      throw new ItWalletSpecsVersionError(
        "version-dispatcher",
        version,
        Object.keys(handlers),
      );
    }
    return handler(options);
  };
}

/**
 * Dispatches by a bare version value (no options object needed).
 *
 * @param version     - The version to dispatch on
 * @param handlers    - Map of version → zero-argument handler function
 * @returns Result returned by the selected version handler.
 * @throws {ItWalletSpecsVersionError} If no handler is registered for the version.
 */
export function dispatchByVersion<TResult>(
  version: ItWalletSpecsVersion,
  handlers: Required<Record<ItWalletSpecsVersion, () => TResult>>,
): TResult {
  const handler = handlers[version];
  if (typeof handler !== "function") {
    throw new ItWalletSpecsVersionError(
      "version-dispatcher",
      version,
      Object.keys(handlers),
    );
  }
  return handler();
}
