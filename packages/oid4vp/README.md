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

The `parseAuthorizeRequest` function verifies a JWT containing a Request Object and determines the correct public key for signature verification based on the IT Wallet specifications.

#### Public Key Resolution Priority

The function follows this priority order to determine which public key to use for JWT verification:

1. **`x509_hash#` prefix in `client_id`** - Uses `x5c` certificate chain from header
2. **`openid_federation#` prefix or no prefix in `client_id`** (default method) - Extracts RP metadata from the `trust_chain` array in the JWT header

**Important**: 
- When the `client_id` uses the `openid_federation#` prefix or has no prefix, the `trust_chain` MUST be present in the JWT header
- Any `client_metadata` present in the request object MUST be ignored when using `openid_federation#` prefix
- The RP metadata is automatically extracted from the first JWT in the `trust_chain` array

```typescript
import { parseAuthorizeRequest } from '@pagopa/io-wallet-oid4vp';
import { ItWalletCredentialVerifierMetadata } from '@pagopa/io-wallet-oid-federation';

// Request Object JWT containing the requested credentials obtained from the RP
const requestObjectJwt = "ey..." 

// Prepare the callbacks
const callbacks = {
    verifyJwt : async (signer, {header, payload, compact}) => {
        const result = //signature verification
        return {
            verified : result,
            signerJwk : signer.publicJwk //Mandatory only if signature is verified correctly
        }
    }
}

// Decode, verify and return the Request Object
// The RP metadata is automatically extracted from the trust_chain in the JWT header
// when client_id has openid_federation# prefix or no prefix
const parsedRequestObject = await parseAuthorizeRequest({
    requestObjectJwt,
    callbacks
});
```

#### Specific Scenarios

##### Scenario 1: x509_hash# prefix - Using client_metadata

When the `client_id` uses the `x509_hash#` prefix, the public key is obtained from the `client_metadata.jwks` field in the Request Object:

```typescript
// Request Object with:
// - client_id = "x509_hash#abc123..."
// - x5c included jwt
const parsedRequestObject = await parseAuthorizeRequest({
    requestObjectJwt,
    callbacks,
});
```

##### Scenario 2: openid_federation# prefix - Using Trust Chain

When the `client_id` uses the `openid_federation#` prefix, the RP metadata is automatically extracted from the `trust_chain` array in the JWT header. Any `client_metadata` in the Request Object is ignored:

```typescript
// Request Object with:
// - client_id = "openid_federation#https://rp.example.org"
// - header.trust_chain = ["<RP Entity Configuration JWT>", ...]
const parsedRequestObject = await parseAuthorizeRequest({
    requestObjectJwt,
    callbacks,
});
// RP metadata is automatically extracted from trust_chain[0]
```

### Fetching Authorization Requests

The `fetchAuthorizationRequest` function handles authorization requests from QR codes or deep links, supporting both transmission modes defined in IT-Wallet specifications.

#### Transmission Modes

**By Value** (IT-Wallet v1.3+): Request Object JWT embedded directly in URL

```typescript
import { fetchAuthorizationRequest } from '@pagopa/io-wallet-oid4vp';

const qrCodeUrl =
  "https://wallet.example.org/authorize?" +
  "client_id=openid_federation%23https%3A%2F%2Frp.example.org" +
  "&request=eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ...";

const result = await fetchAuthorizationRequest({
  authorizeRequestUrl: qrCodeUrl,
  callbacks: {
    fetch: globalThis.fetch,
    verifyJwt: myJwtVerifier,
  },
});

console.log(result.sendBy); // "value"
console.log(result.parsedAuthorizeRequest); // Parsed request
```

**By Reference with GET** (IT-Wallet v1.0+): Request Object fetched from separate endpoint

```typescript
const qrCodeUrl =
  "https://wallet.example.org/authorize?" +
  "client_id=openid_federation%23https%3A%2F%2Frp.example.org" +
  "&request_uri=https%3A%2F%2Frp.example.org%2Frequest";

const result = await fetchAuthorizationRequest({
  authorizeRequestUrl: qrCodeUrl,
  callbacks: {
    fetch: globalThis.fetch,
    verifyJwt: myJwtVerifier,
  },
});

console.log(result.sendBy); // "reference"
console.log(result.parsedQrCode.requestUriMethod); // "get" (default when request_uri_method is omitted)
```

**By Reference with POST and Wallet Metadata** (IT-Wallet v1.3+): Sends wallet capabilities

```typescript
const qrCodeUrl =
  "https://wallet.example.org/authorize?" +
  "client_id=openid_federation%23https%3A%2F%2Frp.example.org" +
  "&request_uri=https%3A%2F%2Frp.example.org%2Frequest" +
  "&request_uri_method=post";

const result = await fetchAuthorizationRequest({
  authorizeRequestUrl: qrCodeUrl,
  callbacks: {
    fetch: globalThis.fetch,
    verifyJwt: myJwtVerifier,
  },
  // Optional: Send wallet capabilities per IT-Wallet v1.3 spec
  walletMetadata: {
    authorization_endpoint: "https://wallet.example.org/authorize",
    response_types_supported: ["vp_token"],
    response_modes_supported: ["direct_post.jwt"],
    vp_formats_supported: {
      jwt_vc_json: {
        alg_values_supported: ["ES256", "ES384"]
      }
    }
  },
  // Optional: Nonce for replay attack prevention
  walletNonce: "random-nonce-value",
});

console.log(result.sendBy); // "reference"
console.log(result.parsedQrCode.requestUriMethod); // "post"
// POST body sent: wallet_metadata={"authorization_endpoint"...}&wallet_nonce=random-nonce-value
```

#### API Reference

```typescript
export interface FetchAuthorizationRequestOptions {
  /**
   * The authorization URL from the QR code
   * Should contain `client_id` and either `request` or `request_uri` query parameters
   */
  authorizeRequestUrl: string;

  /**
   * Callback functions for making HTTP requests and JWT verification
   */
  callbacks: Pick<CallbackContext, "fetch" | "verifyJwt">;

  /**
   * Optional wallet metadata to send when request_uri_method=post.
   * Per IT-Wallet v1.3.3 spec, the Wallet Instance SHOULD transmit
   * its capabilities to allow dynamic request adjustment.
   */
  walletMetadata?: {
    authorization_endpoint?: string;
    response_types_supported?: string[];
    response_modes_supported?: string[];
    vp_formats_supported?: Record<string, unknown>;
    request_object_signing_alg_values_supported?: string[];
    client_id_prefixes_supported?: string[];
  };

  /**
   * Optional wallet nonce for replay attack prevention.
   * RECOMMENDED per IT-Wallet v1.3.3 specification.
   */
  walletNonce?: string;
}

export interface FetchAuthorizationRequestResult {
  /**
   * Parsed and verified authorization request object
   */
  parsedAuthorizeRequest: ParsedAuthorizeRequestResult;

  /**
   * Parsed QR code data including clientId, requestUri, and requestUriMethod
   */
  parsedQrCode: ParsedQrCode;

  /**
   * Transmission mode indicator
   * - "value": Request Object JWT passed inline via `request` parameter
   * - "reference": Request Object JWT fetched from `request_uri`
   */
  sendBy: "reference" | "value";
}
```

#### Error Handling

```typescript
import {
  fetchAuthorizationRequest,
  InvalidRequestUriMethodError,
  Oid4vpError,
  ParseAuthorizeRequestError
} from '@pagopa/io-wallet-oid4vp';
import { ValidationError } from '@openid4vc/utils';

try {
  const result = await fetchAuthorizationRequest({
    authorizeRequestUrl: url,
    callbacks: { fetch, verifyJwt },
  });
} catch (error) {
  if (error instanceof InvalidRequestUriMethodError) {
    // Invalid request_uri_method value (not "get" or "post")
    console.error("Invalid HTTP method:", error.message);
  } else if (error instanceof Oid4vpError) {
    // URL parsing, parameter validation, or HTTP fetch errors
    console.error("Request fetch failed:", error.message);
  } else if (error instanceof ParseAuthorizeRequestError) {
    // JWT verification or signature validation errors
    console.error("JWT verification failed:", error.message);
  } else if (error instanceof ValidationError) {
    // JWT structure validation errors (Zod schema)
    console.error("Invalid structure:", error.message);
  }
}
```

**Error Types:**
- `InvalidRequestUriMethodError`: Thrown when `request_uri_method` is not "get" or "post"
- `Oid4vpError`: URL parsing, mutual exclusivity, or HTTP fetch failures
- `ParseAuthorizeRequestError`: JWT signature verification failures
- `ValidationError`: Zod schema validation failures (JWT structure, URL parameters)

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
   * Optional algorithm for signing the authorization response (JARM).
   * Required when using v1.3 RP metadata that doesn't include this field.
   * Defaults to ES256 if not provided.
   */
  authorization_signed_response_alg?: string;

  /**
   * Optional algorithm for encrypting the authorization response (JARM).
   * Required when using v1.3 RP metadata that doesn't include this field.
   * Defaults to ECDH-ES for EC keys if not provided.
   */
  authorization_encrypted_response_alg?: string;

  /**
   * Optional content encryption encoding for the authorization response (JARM).
   * Required when using v1.3 RP metadata that doesn't include this field.
   * Falls back to first value in encrypted_response_enc_values_supported or A256GCM.
   */
  authorization_encrypted_response_enc?: string;

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
   * OpenID Federation Relying Party metadata.
   * Supports both v1.0 and v1.3 credential verifier metadata.
   */
  rpMetadata: ItWalletCredentialVerifierMetadata | ItWalletCredentialVerifierMetadataV1_3;

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

```typescript
export class InvalidRequestUriMethodError extends Oid4vpError {
  constructor(message: string) {
    super(message);
    this.name = "InvalidRequestUriMethodError";
  }
}
```
Error thrown when `request_uri_method` parameter has an invalid value. Valid values are "get" or "post" (case-insensitive).