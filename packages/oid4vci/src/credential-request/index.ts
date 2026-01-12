export * from "./create-credential-request";
export * from "./fetch-credential-response";
export type * from "./types";

// Re-export version-specific fetch types
export type { FetchCredentialResponseOptionsV1_0_2 } from "./v1.0.2/fetch-credential-response";
// Re-export version-specific types and schemas (not the createCredentialRequest implementations)
export type {
  CredentialRequestV1_0_2,
  CredentialResponseV1_0_2,
} from "./v1.0.2/z-credential";

export {
  zCredentialRequestV1_0_2,
  zCredentialResponseV1_0_2,
} from "./v1.0.2/z-credential";
export type { FetchCredentialResponseOptionsV1_3_3 } from "./v1.3.3/fetch-credential-response";

export type {
  CredentialRequestV1_3_3,
  CredentialResponseV1_3_3,
} from "./v1.3.3/z-credential";
export {
  zCredentialRequestV1_3_3,
  zCredentialResponseV1_3_3,
} from "./v1.3.3/z-credential";

// Legacy exports for backward compatibility (deprecated - use version-specific types)
export { zCredentialRequest, zCredentialResponse } from "./z-credential";
export type { CredentialResponse } from "./z-credential";
