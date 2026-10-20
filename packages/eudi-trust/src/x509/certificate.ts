import { decodeBase64 } from "@pagopa/io-wallet-utils";

/**
 * Canonical form of a base64 or base64url DER certificate, ignoring whitespace,
 * alphabet and padding, so that equal certificates compare equal.
 */
export function normalizeCertificate(certificate: string): string {
  const unpadded = certificate
    .replace(/\s/g, "")
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  let end = unpadded.length;
  while (end > 0 && unpadded[end - 1] === "=") end--;

  return unpadded.slice(0, end);
}

export function includesCertificate(
  certificates: string[],
  certificate: string,
): boolean {
  const normalized = normalizeCertificate(certificate);
  return certificates.some((c) => normalizeCertificate(c) === normalized);
}

/**
 * Canonical form of a hexadecimal key identifier, ignoring the case
 * and any `:` or whitespace separator.
 */
export function normalizeKeyIdentifier(keyIdentifier: string): string {
  return keyIdentifier.replace(/[\s:]/g, "").toLowerCase();
}

/**
 * Hexadecimal form of a key identifier encoded in base64 (or base64url),
 * or undefined if it is not valid base64.
 */
export function base64ToKeyIdentifier(base64: string): string | undefined {
  try {
    return Array.from(decodeBase64(base64), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
  } catch {
    return undefined;
  }
}

/**
 * Canonical form of a Distinguished Name string (RFC 4514 or RFC 2253), ignoring
 * the case, the spacing and the order of its RDNs, so that the same name written
 * by different producers compares equal.
 */
export function normalizeDistinguishedName(name: string): string {
  return name
    .split(/(?<!\\),/)
    .map((rdn) =>
      rdn
        .trim()
        .replace(/\s*=\s*/, "=")
        .toLowerCase(),
    )
    .filter((rdn) => rdn.length > 0)
    .sort()
    .join(",");
}
