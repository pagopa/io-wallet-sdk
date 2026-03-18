import { CLOCK_SKEW_TOLERANCE_SECONDS, MAX_IAT_AGE_SECONDS } from "./constants";

export function verifyJwtIatOrThrow(options: { iat: number; now?: Date }) {
  // IT-Wallet freshness policy for proof JWTs: iat must be recent and not too far in the future.
  if (options.iat === undefined) {
    throw new Error("iat claim in JWT is missing");
  }

  const now = options.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);

  if (nowSeconds - options.iat > MAX_IAT_AGE_SECONDS) {
    throw new Error("iat claim in JWT is too old (must be within 5 minutes)");
  }

  if (options.iat - nowSeconds > CLOCK_SKEW_TOLERANCE_SECONDS) {
    throw new Error("iat claim in JWT is too far in the future");
  }
}
