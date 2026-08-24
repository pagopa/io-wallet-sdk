import type { JwkSet } from "@pagopa/io-wallet-utils";

/**
 * Selects an encryption JWK from a JWKS.
 *
 * Selection prefers an explicit `kid`, then keys whose `alg` is supported, then
 * keys marked for encryption or not explicitly marked for signatures.
 *
 * @param jwks - JSON Web Key Set to search.
 * @param options - Optional selection constraints.
 * @param options.kid - Key ID to select directly.
 * @param options.supportedAlgValues - Encryption algorithms accepted by the caller.
 * @returns Matching encryption JWK, or the first available key when no better match exists.
 */
export function extractEncryptionJwkFromJwks(
  jwks: JwkSet,
  {
    kid,
    supportedAlgValues,
  }: {
    kid?: string;
    supportedAlgValues?: string[];
  },
) {
  if (kid) {
    return jwks.keys.find((jwk) => jwk.kid === kid);
  }

  let algFiltered = jwks.keys.filter(
    (key) => key.alg && supportedAlgValues?.includes(key.alg),
  );
  if (algFiltered.length === 0) algFiltered = jwks.keys;

  let encFiltered = algFiltered.filter((key) => key.use === "enc");
  if (encFiltered.length === 0) {
    encFiltered = algFiltered.filter((key) => key.use !== "sig");
  }

  return encFiltered.length > 0 ? encFiltered[0] : jwks.keys[0];
}
