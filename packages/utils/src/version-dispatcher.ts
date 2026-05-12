import { ItWalletSpecsVersion } from "./config";

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
 * An unknown version value supplied at runtime via an unsafe enum cast
 * will produce a `TypeError` rather than an `ItWalletSpecsVersionError`.
 * Both `createVersionDispatcher` and `dispatchByVersion` share this contract.
 *
 * @param handlers - Map of version → handler function (all versions required)
 */
export function createVersionDispatcher<
  TOptions extends VersionedOptions,
  TResult,
>(
  handlers: Required<
    Record<ItWalletSpecsVersion, (options: TOptions) => TResult>
  >,
): (options: TOptions) => TResult {
  return (options: TOptions): TResult =>
    handlers[options.config.itWalletSpecsVersion](options);
}

/**
 * Dispatches by a bare version value (no options object needed).
 *
 * All versions declared in `ItWalletSpecsVersion` must be provided
 * (`Required` contract). See `createVersionDispatcher` for the rationale.
 *
 * @param version  - The version to dispatch on
 * @param handlers - Map of version → zero-argument handler function (all versions required)
 */
export function dispatchByVersion<TResult>(
  version: ItWalletSpecsVersion,
  handlers: Required<Record<ItWalletSpecsVersion, () => TResult>>,
): TResult {
  return handlers[version]();
}
