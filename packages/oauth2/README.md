## @pagopa/io-wallet-oauth2

This package provides functionalities to manage the **OAuth 2.0** part of the **OpenID for Verifiable Credentials Issuance (OID4VCI)** and **OpenID for Verifiable Presentations (OIDVP)** protocol flows, specifically tailored for the Italian Wallet ecosystem.

## Installation

To install the package, use your preferred package manager:

```bash
# Using pnpm
pnpm add @pagopa/io-wallet-oauth2

# Using yarn
yarn add @pagopa/io-wallet-oauth2
```

## Usage

### `createTokenDPoP`

```typescript
import { JwtSignerJwk, createTokenDPoP, CreateTokenDPoPOptions, HttpMethod } from "@pagopa/io-wallet-oauth2"

const signer: JwtSignerJwk = {
    method: 'jwk',
    publicJwk: {/* JWK description here */},
    alg: 'ES256'
}

/**
 * Scenario 1: Basic DPoP for token request
 */

const callbacks = {
  signJwt: (signer: JwtSignerJwk, {header, payload}) => {/* Perform JWT signing */},
  hash: (data: Uint8Array, algorithm: HashAlgorithm) => {/* Perform hash operation */},
  generateRandom: (byteLength: number) => {/* Generate an Uint8Array containing a sequence of byteLength random bytes */}
}

const options: CreateTokenDPoPOptions = {
    callbacks,
    signer,
    tokenRequest: {
        method: HttpMethod.Post,
        url: 'https://example.com/token'
    }
}

const jwt = await createTokenDPoP(options)

/**
 * End Scenario 1
 */

/**
 * Scenario 2: DPoP bound to an access token
 */

const callbacks = {
  signJwt: (signer: JwtSignerJwk, {header, payload}) => {/* Perform JWT signing */},
  hash: (data: Uint8Array, algorithm: HashAlgorithm) => {/* Perform hash operation */},
  generateRandom: (byteLength: number) => {/* Generate random bytes */}
}

const options: CreateTokenDPoPOptions = {
    callbacks,
    signer,
    tokenRequest: {
        method: HttpMethod.Post,
        url: 'https://example.com/resource'
    },
    accessToken: 'your_access_token_here'
}

const jwt = await createTokenDPoP(options)

/**
 * End Scenario 2
 */

```

## API Reference

### `createTokenDPoP`

```typescript
/**
 * Options for Token Request DPoP generation
 */
export interface CreateTokenDPoPOptions {
  /**
   * The access token to which the dpop jwt should be bound. Required
   * when the dpop will be sent along with an access token.
   *
   * If provided, the `hash` callback parameter also needs to be provided
   */
  accessToken?: string;

  /**
   * Object containing callbacks for DPoP generation and signature
   */
  callbacks: Partial<Pick<CallbackContext, "generateRandom">> &
    Pick<CallbackContext, "hash" | "signJwt">;

  /**
   * Creation time of the JWT. If not provided the current date will be used
   */
  issuedAt?: Date;

  /**
   * jti claim for the DPoP JWT. If not provided, a random one will be generated
   * if a generateRandom callback is provided
   */
  jti?: string;

  /**
   * The signer of the dpop jwt. Only jwk signer allowed.
   */
  signer: JwtSignerJwk;

  /**
   * The request for which to create the dpop jwt
   */
  tokenRequest: {
    method: HttpMethod;
    url: string;
  };
}

/**
 * Creates a signed Token DPoP with the given cryptographic material and data.
 * It is used to create DPoP proofs for token requests and credential requests.
 * @param options {@link CreateTokenDPoPOptions}
 * @returns A Promise that resolves with the signed DPoP JWT string
 * @throws {@link CreateTokenDPoPError} in case neither a default jti nor a generateRandom
 *         callback have been provided or the signJwt callback throws
 */ 
async function createTokenDPoP(options: CreateTokenDPoPOptions): Promise<string>
```
### Errors

```typescript
export class Oauth2Error extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "Oauth2Error";
  }
}
```
Generic error thrown on OAuth2 operations

```typescript
export class PushedAuthorizationRequestError extends Oauth2Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "PushedAuthorizationRequestError";
  }
}
```
Custom error thrown when pushed authorization request operations fail

```typescript
export class CreateTokenDPoPError extends Oauth2Error {
  constructor(message: string) {
    super(message);
    this.name = "CreateTokenDPoPError";
  }
}
```
Error thrown in case `createTokenDPoP` is called without neither a custom jti nor a generateRandom callback or when the signJwt callback throws
