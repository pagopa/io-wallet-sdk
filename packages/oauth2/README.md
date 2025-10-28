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



### `fetchTokenResponse`

```typescript
import { fetchTokenResponse, FetchTokenResponseOptions, AccessTokenResponse } from "@pagopa/io-wallet-oauth2"

const callbacks = {
  fetch: (url, options) => {/* Implement fetch logic */}
  ...
}
const accessTokenRequest = createTokenRequest({
    authorizationCode: "authorization_code_here",
    pkceCodeVerifier: "code_verifier_here",
    callbacks,
    redirect_uri: "https://client.example.com/callback"
  });
const options: FetchTokenResponseOptions = {
  accessTokenEndpoint: "https://authorization-server.example.com/token",
  accessTokenRequest,
  callbacks,
  clientAttestationDPoP: "eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0In0...",
  walletAttestation: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}

const tokenResponse: AccessTokenResponse = await fetchTokenResponse(options)
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


### `fetchTokenResponse`

```typescript
/**
 * Options for fetching an access token response
 */
export interface FetchTokenResponseOptions {
  /**
   * The endpoint URL where the access token request will be sent
   * This should be the authorization server's token endpoint
   */
  accessTokenEndpoint: string;

  /**
   * The access token request payload
   */
  accessTokenRequest: AccessTokenRequest;

  /**
   * Callbacks to use for requesting access token
   */
  callbacks: Pick<CallbackContext, "fetch">;

  /**
   * The client attestation Demonstration of Proof-of-Possession (DPoP) token
   * Used for OAuth-Client-Attestation-PoP header to prove possession of the client key
   */
  clientAttestationDPoP: string;

  /**
   * The wallet attestation JWT that proves the client's identity and capabilities
   * Used for OAuth-Client-Attestation header
   */
  walletAttestation: string;
}

/**
 * Access token request payload
 */
export type AccessTokenRequest = {
  grant_type: "authorization_code" | "refresh_token";
  code?: string;
  code_verifier?: string;
  redirect_uri?: string;
  refresh_token?: string;
  [key: string]: unknown;
}

/**
 * Access token response
 */
export type AccessTokenResponse = {
  access_token: string;
  token_type: "DPoP";
  expires_in?: number;
  refresh_token?: string;
  authorization_details?: Array<{
    type: "openid_credential";
    credential_configuration_id?: string;
    credential_identifiers?: string[];
    [key: string]: unknown;
  }>;
  [key: string]: unknown;
}

/**
 * Sends an access token request to the authorization server and returns the response
 * @param options {@link FetchTokenResponseOptions}
 * @returns A Promise that resolves with the parsed access token response
 * @throws {@link UnexpectedStatusCodeError} When the server returns a non-200 status code
 * @throws {@link ValidationError} When the response cannot be parsed as a valid access token response
 * @throws {@link FetchTokenResponseError} When an unexpected error occurs during the request
 */
async function fetchTokenResponse(options: FetchTokenResponseOptions): Promise<AccessTokenResponse>
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

```typescript
export class FetchTokenResponseError extends Oauth2Error {
  constructor(message: string) {
    super(message);
    this.name = "FetchTokenResponseError";
  }
}
```
Error thrown when an unexpected error occurs during the access token request