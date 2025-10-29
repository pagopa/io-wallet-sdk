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
} as const;
