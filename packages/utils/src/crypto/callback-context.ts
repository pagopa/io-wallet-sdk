import type { Fetch, FetchHeaders } from "../globals";
import type { HttpMethod } from "../validation";
import type { HashCallback } from "./hash";
import type { Jwk } from "./jwk/z-jwk";
import type {
  JweEncryptor,
  JwtHeader,
  JwtPayload,
  JwtSigner,
  JwtSignerJwk,
} from "./jwt/z-jwt";

import { ContentType } from "../content-type";

type OrPromise<T> = Promise<T> | T;

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

export interface ClientAuthenticationCallbackOptionsBase<
  AuthorizationServerMetadata = unknown,
> {
  authorizationServerMetadata: AuthorizationServerMetadata;
  body: Record<string, unknown>;
  contentType: ContentType;
  headers: FetchHeaders;
  method: HttpMethod;
  url: string;
}

export type ClientAuthenticationCallbackOptions<
  AuthorizationServerMetadata = unknown,
  ExtraOptions extends object = object,
> = ClientAuthenticationCallbackOptionsBase<AuthorizationServerMetadata> &
  ExtraOptions;

export type ClientAuthenticationCallback<
  Options extends ClientAuthenticationCallbackOptions =
    ClientAuthenticationCallbackOptions,
> = (options: Options) => OrPromise<void>;

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
