## @pagopa/io-wallet-oid4vp

This package provides functionalities to manage the **OpenID for Verifiable Presentations (OID4VP)** protocol flow, specifically tailored for the Italian Wallet ecosystem, simplifying QEAA credentials issuance and credentials presentations.

## Installation

To install the package, use your preferred package manager:

```bash
# Using pnpm
pnpm add @pagopa/io-wallet-oid4vp

# Using yarn
yarn add @pagopa/io-wallet-oid4vp
```

## Usage

### Verifying a received Request object

```typescript
import { parseAuthorizeRequest } from '@pagopa/io-wallet-oid4vp';

//Request Object JWT containing the requested credentials obtained from the RP
const requestObjectJwt = "ey..." 

//Obtain the signer
const signer = {
    method : 'jwk',
    publicJwk : {/*... jwk details*/},
    alg : 'ES256'
}

//Prepare the callbacks
const callbacks = {
    verifyJwt : async (signer, {header, payload, compact}) => {
        const result = //signature verification
        return {
            verified : result,
            signerJwk : signer.publicJwk //Mandatory only if signature is verified correctly
        }
    }
}

//Decode, verify and return the Request Object
const parsedRequestObject = await parseAuthorizeRequest({
    requestObjectJwt,
    callbacks,
    dpop : {signer}
});
```

### Generating an Authorization Response

```typescript
import { createAuthorizationResponse, AuthorizationRequestObject } from '@pagopa/io-wallet-oid4vp';
import { ItWalletCredentialVerifierMetadata } from "@pagopa/io-wallet-oid-federation";

//Obtain the RP's metadata
const rpMetadata : ItWalletCredentialVerifierMetadata = {
  ...
}

//Obtain a decoded Request Object from, e.g., parseAuthorizeRequest invocation
const requestObject: AuthorizationRequestObject = {
  ...
}

//Obtain the signer
const signer = {
    method : 'jwk',
    publicJwk : {/*... jwk details*/},
    alg : 'ES256'
}

//Obtain the vp_token
const vp_token = {
  ... //VP token containing the attributes to disclose
}

//Prepare the callbacks
const callbacks = {
    encryptJwe : async (jweEncryptor, data) => {
        const result = encrypt(data, jweEncryptor)
        return {
            verified : result,
            encryptionJwk : jweEncryptor
        }
    },
    fetch : async (input, init) => {
      ...//Fetch implementation
    },
    generateRandom : async (number) => new Uint8Array(number),
    signJwt : async (jwtSigner, {header, payload}) => {
      const str = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(body))}`
      const sig = signJwt(jwtSigner, str)
      return `${str}.${sig}`
    }
}

//Create the response

const resp = createAuthorizationResponse({
  callbacks,
  client_id : "JWK Thumbprint",
  requestObject,
  rpMetadata,
  signer,
  vp_token
})

```

## API Reference

### AuthorizationRequestObject type and Zod parser
```typescript
export const zVpFormatsSupported = z.record(
  z.string(),
  z
    .object({
      alg_values_supported: z.optional(z.array(z.string())),
    })
    .passthrough(),
);

export type VpFormatsSupported = z.infer<typeof zVpFormatsSupported>;

export const zClientMetadata = z
  .object({
    client_name: z.string().optional(),
    encrypted_response_enc_values_supported: z.array(z.string()).optional(),
    jwks: z.object({ keys: z.array(zJwk) }).passthrough(),
    logo_uri: z.string().url().optional(),
    vp_formats_supported: zVpFormatsSupported,
  })
  .passthrough();

export type ClientMetadata = z.infer<typeof zClientMetadata>;

export const zOpenid4vpAuthorizationRequestPayload = z
  .object({
    response_type: z.literal('vp_token'),
    client_id: z.string(),
    client_metadata: zClientMetadata.optional(),
    response_uri: z.string().url().optional(),
    request_uri: z.string().url().optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.literal("direct_post.jwt"),
    nonce: z.string(),
    wallet_nonce: z.string().optional(),
    scope: z.string().optional(),
    dcql_query: z.record(z.string(), z.any()).optional(),
    state: z.string().optional(),
    transaction_data_hashes_alg: z.array(z.string()).optional(),
  })
  .passthrough().and(zJwtPayload)

export type AuthorizationRequestObject = z.infer<typeof zOpenid4vpAuthorizationRequestPayload>
```

### parseAuthorizeRequest
```typescript
export interface ParseAuthorizeRequestOptions {
    /**
     * The Authorization Request Object JWT.
     */
    requestObjectJwt : string ;

    /**
     * Callback context for signature verification.
     */
    callbacks : Pick<CallbackContext, 'verifyJwt'>

    /**
     * DPoP options
     */
    dpop: RequestDpopOptions
}

export async function parseAuthorizeRequest(options: ParseAuthorizeRequestOptions) : Promise<AuthorizationRequestObject> {
    ...
}
```
This method receives a Request Object in JWT format, verifies the signature and returns the decoded Request Object.

### createAuthorizationResponse
```typescript
export interface CreateAuthorizationResponseOptions {
  /**
   * Callbacks for authorization response generation
   */
  callbacks: Pick<
    CallbackContext,
    "encryptJwe" | "fetch" | "generateRandom" | "signJwt"
  >;

  /**
   * Thumbprint of the JWK in the cnf Wallet Attestation
   */
  client_id: string;

  /**
   * Optional expiration of the Authorization Response JWT, defaults to 10 minutes
   */
  exp?: number;

  /**
   * Presentation's Request Object
   */
  requestObject: AuthorizationRequestObject;

  /**
   * OpenID Federation Relying Party metadata
   */
  rpMetadata: ItWalletCredentialVerifierMetadata;

  /**
   * Signer created from the Wallet Instance's private key
   */
  signer: JwtSigner;

  /**
   * Array containing the vp_tokens of the credentials
   * to present
   */
  vp_token: VpToken;
}

export async function createAuthorizationResponse(
  options: CreateAuthorizationResponseOptions,
) {
  ...
}
```
This method receives the RequestObject, its resolved VP Tokens and other necessary cryptographic and configuration data and returns a signed Authorization Response

### Errors

```typescript
export class Oid4vpError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "Oid4vpError";
  }
}
```
Generic package level error class which every other package error should extend.

```typescript
export class ParseAuthorizeRequestError extends Oid4vpError {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "ParseAuthorizeRequestError";
  }
}
```
Error thrown by `parseAuthorizeRequest` when the passed request object has an invalid signature or unexpected errors are thrown.

```typescript
export class CreateAuthorizationResponseError extends Oid4vpError {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "CreateAuthorizationResponseError";
  }
}
```
Error thrown by `createAuthorizationResponse` in case there are unexpected errors.