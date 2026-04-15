export * from "./access-token";
export * from "./authorization-request";
export * from "./client-attestation";
export * from "./common";
export * from "./errors";
export * from "./jar";
export * from "./jarm-form-post-jwt";
export * from "./mrtd-pop";
export * from "./pkce";
export * from "./token-dpop";

export {
  /** @deprecated Use `CallbackContext` from `@pagopa/io-wallet-utils` instead. */
  type CallbackContext,
  type ClientAttestationPopJwtHeader,
  type ClientAttestationPopJwtPayload,
  type DecryptJweCallback,
  type EncryptJweCallback,
  type GenerateRandomCallback,
  HashAlgorithm,
  type JweEncryptor,
  type JwtSigner,
  /** @deprecated Use `JwtSignerJwk` from `@pagopa/io-wallet-utils` instead. */
  type JwtSignerJwk,
  Oauth2JwtParseError,
  type RequestDpopOptions,
  type SignJwtCallback,
  type VerifyJwtCallback,
  verifyJwt,
} from "@openid4vc/oauth2";
