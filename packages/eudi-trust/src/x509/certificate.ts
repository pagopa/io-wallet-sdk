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
