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
 * @param handlers - Map of version → handler function (all versions required)
 * @throws {ItWalletSpecsVersionError} When an unknown version is supplied at runtime
 * (e.g. via an unsafe enum cast or external configuration)
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
 * All versions declared in `ItWalletSpecsVersion` must be provided
 * (`Required` contract). See `createVersionDispatcher` for the rationale.
 *
 * @param version  - The version to dispatch on
 * @param handlers - Map of version → zero-argument handler function (all versions required)
 * @throws {ItWalletSpecsVersionError} When an unknown version is supplied at runtime
 * (e.g. via an unsafe enum cast or external configuration)
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
