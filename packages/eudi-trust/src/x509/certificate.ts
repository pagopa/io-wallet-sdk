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
 * Base64 form of a hexadecimal key identifier, ignoring the case
 * and any `:` or whitespace separator.
 */
export function keyIdentifierToBase64(keyIdentifier: string): string {
  const hex = keyIdentifier.replace(/[\s:]/g, "");
  const bytes = (hex.match(/../g) ?? []).map((pair) => parseInt(pair, 16));
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Canonical form of a Distinguished Name string (RFC 4514 or RFC 2253), ignoring
 * the case, the spacing and the order of its RDNs, so that the same name written
 * by different producers compares equal.
 */
export function normalizeDistinguishedName(name: string): string {
  return name
    .split(/(?<!\\),/)
    .map((rdn) => {
      const separator = rdn.indexOf("=");
      return (
        separator === -1
          ? rdn.trim()
          : `${rdn.slice(0, separator).trim()}=${rdn.slice(separator + 1).trim()}`
      ).toLowerCase();
    })
    .filter((rdn) => rdn.length > 0)
    .sort()
    .join(",");
}
