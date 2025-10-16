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
import { JwtSigner, createTokenDPoP, CreateTokenDPoPOptions } from "@pagopa/io-wallet-oauth2"

const header = {
    alg : 'ES256'
}

const signer : JwtSigner = {
    method : 'jwk',
    publicJwk : {/* JWK description here */},
    alg : 'ES256' //Should match the header alg param, but behavior depends on the callback
}

/**
 * Scenario 1, generateRandom provided
 */

const callbacks : {
  signJwt : (signer : JwtSigner, {header, payload}) => {/* Perform JWT signing */}
  generateRandom : (byteLenght: number) => {/* Generate an Uint8Array containing a sequence of byteLenght random bytes */}
}

const payload = {
    htm : 'POST',
    htu : 'example_htu',
}

/**
 * End Scenario 1
 */

/**
 * Scenario 2, jti provided
 */

const callbacks : {
  signJwt : (signer : JwtSigner, {header, payload}) => {/* Perform JWT signing */}
}

const payload = {
    htm : 'POST',
    htu : 'example_htu',
    jti : 'custom_jti_here'
}

/**
 * End Scenario 2
 */

const options : CreateTokenDPoPOptions = {
    callbacks,
    header,
    payload,
    signer
}

const {jwt, signerJwk} = await createTokenDPoP(options)

```

## API Reference

### `createTokenDPoP`

```typescript
/**
 * Options for Token Request DPoP generation
 */
export interface CreateTokenDPoPOptions {
  /**
   * Object containing callbacks for DPoP generation and signature
   */
  callbacks: Partial<Pick<CallbackContext, "generateRandom">> &
    Pick<CallbackContext, "signJwt">;

  /**
   * Customizable headers for DPoP signing.
   * As per technical specifications, the key typ will be set to 'dpop+jwt',
   * overriding any custom value passed. In case the alg and jwk properties
   * will not be set, the responsibility of doing so is left to the signJwt
   * callback, which may as well override such keys if passed
   */
  header: { alg: string } & Record<string, unknown>;

  /**
   * Customizable payload for DPoP signing.
   * Any field might be overridden by the signJwt callback
   */
  payload: {
    htm: HttpMethod;
    htu: string;
    jti?: string;
  } & Record<string, unknown>;

  /**
   * Jwt Signer corresponding to the DPoP's Crypto Context
   */
  signer: JwtSigner;
}

/**
 * Creates a signed Token DPoP with the given cryptographic material and data.
 * @param options {@link CreateTokenDPoPOptions}
 * @returns A Promise that resolves with an object containing the signed DPoP JWT and
 *          its corresponding public JWK
 * @throws {@link CreateTokenDPoPError} in case neither a default jti nor a generateRandom
 *         callback have been provided or the signJwt callback throws
 */ 
async function createTokenDPoP(options: CreateTokenDPoPOptions) : Promise<{jwt : string, signerJwk : Jwk}>
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
