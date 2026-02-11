import {
  type CredentialResponseV1_0,
  zCredentialResponseV1_0,
} from "./v1.0/z-credential-response";
import {
  type CredentialResponseV1_3,
  zCredentialResponseV1_3,
} from "./v1.3/z-credential-response";

/**
 * Unified credential response type that can be either v1.0.2 or v1.3.3 format
 */
export type CredentialResponse =
  | CredentialResponseV1_0
  | CredentialResponseV1_3;

// Re-export version-specific types and schemas
export type { CredentialResponseV1_0, CredentialResponseV1_3 };
export { zCredentialResponseV1_0, zCredentialResponseV1_3 };
