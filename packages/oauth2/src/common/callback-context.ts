import type { Fetch, FetchHeaders, HttpMethod } from "@pagopa/io-wallet-utils";

import { ContentType } from "@pagopa/io-wallet-utils";

import type { HashCallback } from "./hash";
import type { Jwk } from "./jwk/z-jwk";
import type {
  JweEncryptor,
  JwtHeader,
  JwtPayload,
  JwtSigner,
  JwtSignerJwk,
} from "./jwt/z-jwt";

type OrPromise<T> = Promise<T> | T;

export interface ClientAuthenticationCallbackOptions {
  authorizationServerMetadata: Record<string, unknown>;
  body: Record<string, unknown>;
  contentType: ContentType;
  headers: FetchHeaders;
  method: HttpMethod;
  url: string;
}

export type ClientAuthenticationCallback = (
  options: ClientAuthenticationCallbackOptions,
) => OrPromise<void>;

export type GenerateRandomCallback = (
  byteLength: number,
) => OrPromise<Uint8Array>;

export type SignJwtCallback = (
  jwtSigner: JwtSigner,
  jwt: {
    header: JwtHeader;
    payload: JwtPayload;
  },
) => OrPromise<{
  jwt: string;
  signerJwk: Jwk;
}>;

export type VerifyJwtCallback = (
  jwtSigner: JwtSigner,
  jwt: {
    compact: string;
    header: JwtHeader;
    payload: JwtPayload;
  },
) => OrPromise<
  | {
      signerJwk: Jwk;
      verified: true;
    }
  | {
      signerJwk?: Jwk;
      verified: false;
    }
>;

export type DecryptJweCallback = (
  jwe: string,
  options?: { jwk?: Jwk },
) => OrPromise<
  | {
      decrypted: false;
      decryptionJwk?: Jwk;
      payload?: string;
    }
  | {
      decrypted: true;
      decryptionJwk: Jwk;
      payload: string;
    }
>;

export type EncryptJweCallback = (
  jweEncryptor: JweEncryptor,
  data: string,
) => OrPromise<{
  encryptionJwk: Jwk;
  jwe: string;
}>;

export interface CallbackContext {
  clientAuthentication: ClientAuthenticationCallback;
  decryptJwe: DecryptJweCallback;
  encryptJwe: EncryptJweCallback;
  fetch?: Fetch;
  generateRandom: GenerateRandomCallback;
  getX509CertificateMetadata?: (certificate: string) => {
    sanDnsNames: string[];
    sanUriNames: string[];
  };
  hash: HashCallback;
  signJwt: SignJwtCallback;
  verifyJwt: VerifyJwtCallback;
}

export interface RequestDpopOptions {
  nonce?: string;
  signer: JwtSignerJwk;
}
