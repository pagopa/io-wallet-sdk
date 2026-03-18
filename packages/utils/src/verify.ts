import { CLOCK_SKEW_TOLERANCE_SECONDS, MAX_IAT_AGE_SECONDS } from "./constants";

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
