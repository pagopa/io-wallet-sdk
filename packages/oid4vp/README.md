## @pagopa/io-wallet-oid4vp

This package provides functionalities to manage the **OpenID for Verifiable Presentations (OID4VP)** protocol flow, specifically tailored for the Italian Wallet ecosystem. It simplifies the creation of wallet attestations required during the credential issuance process.

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

## API Reference

### AuthorizationRequestObject type and Zod parser
```typescript
export const zOpenid4vpAuthorizationRequest = z
  .object({
    response_type: z.literal('vp_token'),
    client_id: z.string(),
    response_uri: z.string().url().optional(),
    request_uri: z.string().url().optional(),
    request_uri_method: z.optional(z.string()),
    response_mode: z.literal("direct_post.jwt"),
    nonce: z.string(),
    wallet_nonce: z.string().optional(),
    scope: z.string().optional(),
    dcql_query: z.record(z.string(), z.any()).optional(),
    state: z.string().optional(),
  })
  .passthrough().and(zJwtPayload)

export type AuthorizationRequestObject = z.infer<typeof zOpenid4vpAuthorizationRequest>
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

### Errors

```typescript
export class AuthorizationRequestParsingError extends Error {
    constructor(message: string) {
        super(message) ;
        this.name = 'AuthorizationRequestParsingError'
    }
}
```
 Error that is thrown when the JWT signature is not verified successfully or other generic errors occur during request object parsing

```typescript
export class Oid4vpParseError extends Error {
    constructor(message : string) {
        super(message);
        this.name = 'Oid4vpParseError'
    }
}
```
Package level error class which wraps parsing and validation errors