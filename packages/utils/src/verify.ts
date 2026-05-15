import { CLOCK_SKEW_TOLERANCE_SECONDS, MAX_IAT_AGE_SECONDS } from "./constants";

/**
 * Validates a JWT `iat` claim against SDK age and clock-skew limits.
 *
 * @param options - Validation options.
 * @param options.iat - Issued-at timestamp in seconds.
 * @param options.now - Optional current date, defaults to the current time.
 * @returns Resolves when the issued-at value is within the accepted time window.
 * @throws {Error} If `iat` is too old or too far in the future.
 */
export function verifyJwtIatOrThrow(options: { iat: number; now?: Date }) {
  const now = options.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);

  if (nowSeconds - options.iat > MAX_IAT_AGE_SECONDS) {
    throw new Error("iat claim in JWT is too old (must be within 5 minutes)");
  }

  if (options.iat - nowSeconds > CLOCK_SKEW_TOLERANCE_SECONDS) {
    throw new Error("iat claim in JWT is too far in the future");
  }
}
