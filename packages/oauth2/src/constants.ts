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
  CONTENT_TYPE: "Content-Type",
  AUTHORIZATION: "Authorization",
  OAUTH_CLIENT_ATTESTATION: "OAuth-Client-Attestation",
  OAUTH_CLIENT_ATTESTATION_POP: "OAuth-Client-Attestation-PoP",
} as const;