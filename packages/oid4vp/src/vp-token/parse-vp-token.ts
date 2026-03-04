import { parseIfJson, parseWithErrorHandling } from "@pagopa/io-wallet-utils";

import { zVpToken } from "./z-vp-token";

export function parseVpToken(vpToken: unknown) {
  return parseWithErrorHandling(
    zVpToken,
    parseIfJson(vpToken),
    "Could not parse dcql vp_token. Expected an object where the values are encoded presentations",
  );
}
