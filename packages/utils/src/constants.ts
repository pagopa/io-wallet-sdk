/**
 * HTTP Content-Type constants for OAuth2 requests
 */
export const CONTENT_TYPES = {
  FORM_URLENCODED: "application/x-www-form-urlencoded",
  JSON: "application/json",
} as const;

/**
 * HTTP Header constants
 */
export const HEADERS = {
  AUTHORIZATION: "Authorization",
  CONTENT_TYPE: "Content-Type",
  OAUTH_CLIENT_ATTESTATION: "OAuth-Client-Attestation",
  OAUTH_CLIENT_ATTESTATION_POP: "OAuth-Client-Attestation-PoP",
  DPOP: "DPoP",
} as const;
