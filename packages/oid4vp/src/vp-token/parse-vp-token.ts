import { parseIfJson, parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import { zVpToken } from "./z-vp-token";

/**
 * Parses a DCQL VP token into the SDK VP token shape.
 *
 * @param vpToken - Raw VP token object or JSON string.
 * @returns Parsed VP token.
 * @throws {ValidationError} If the token is not an object of encoded presentations.
 */
export function parseVpToken(vpToken: unknown) {
  return parseWithErrorHandling(
    zVpToken,
    parseIfJson(vpToken),
    "Could not parse dcql vp_token. Expected an object where the values are encoded presentations",
  );
}
