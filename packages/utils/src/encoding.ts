const utf8Encoder = new TextEncoder();
const utf8Decoder = new TextDecoder();

function base64UrlToBase64(base64: string): string {
  const normalized = base64.replace(/-/g, "+").replace(/_/g, "/");
  const paddingLength = normalized.length % 4;

  return paddingLength === 0
    ? normalized
    : normalized.padEnd(normalized.length + (4 - paddingLength), "=");
}

function base64ToBase64Url(base64: string): string {
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function encodeBase64(data: Uint8Array): string {
  let binary = "";
  for (const byte of data) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function decodeUtf8String(value: string): Uint8Array {
  return utf8Encoder.encode(value);
}

export function encodeToUtf8String(data: Uint8Array): string {
  return utf8Decoder.decode(data);
}

/**
 * Also supports base64 url encoded input.
 */
export function decodeBase64(base64: string): Uint8Array {
  const binary = atob(base64UrlToBase64(base64));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export function encodeToBase64Url(data: Uint8Array | string): string {
  return base64ToBase64Url(
    encodeBase64(typeof data === "string" ? decodeUtf8String(data) : data),
  );
}
