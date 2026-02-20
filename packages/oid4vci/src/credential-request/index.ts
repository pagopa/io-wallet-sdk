export * from "./create-credential-request";
export * from "./fetch-credential-response";
export * from "./parse-credential-request";
export type * from "./types";
// Re-export version-specific types and schemas (not the createCredentialRequest implementations)
export type { CredentialRequestV1_0 } from "./v1.0/z-credential";
export { zCredentialRequestV1_0 } from "./v1.0/z-credential";

// Re-export version-specific fetch types
export type { CredentialRequestV1_3 } from "./v1.3/z-credential";

export { zCredentialRequestV1_3 } from "./v1.3/z-credential";

export * from "./verify-credential-request-jwt-proof";
export * from "./verify-key-attestation-jwt";

export {
  type CredentialResponse,
  type CredentialResponseV1_0,
  type CredentialResponseV1_3,
  zCredentialResponseV1_0,
  zCredentialResponseV1_3,
} from "./z-credential-response";
export * from "./z-proof-jwt";
