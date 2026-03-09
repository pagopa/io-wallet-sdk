## @pagopa/io-wallet-oid4vp

This package provides utilities for the **OpenID for Verifiable Presentations (OID4VP)** flow in the Italian Wallet ecosystem.

## Installation

```bash
# Using pnpm
pnpm add @pagopa/io-wallet-oid4vp

# Using yarn
yarn add @pagopa/io-wallet-oid4vp
```

## Usage

### 1) Fetch authorization request data from QR code / deep link

```typescript
import { fetchAuthorizationRequest } from "@pagopa/io-wallet-oid4vp";

const qrCodeUrl =
  "https://wallet.example.org/authorize?" +
  "client_id=openid_federation%3Ahttps%3A%2F%2Frp.example.org" +
  "&request_uri=https%3A%2F%2Frp.example.org%2Frequest" +
  "&request_uri_method=post";

const requestData = await fetchAuthorizationRequest({
  authorizeRequestUrl: qrCodeUrl,
  callbacks: {
    fetch: globalThis.fetch,
  },
  walletMetadata: {
    authorization_endpoint: "https://wallet.example.org/authorize",
    response_types_supported: ["vp_token"],
    response_modes_supported: ["direct_post.jwt"],
  },
  walletNonce: "random-wallet-nonce",
});

console.log(requestData.sendBy); // "value" | "reference"
console.log(requestData.requestObjectJwt); // JWT request object
console.log(requestData.parsedQrCode.requestUriMethod); // "get" | "post" | undefined
```

### 2) Parse (and optionally verify) the Request Object JWT

`parseAuthorizeRequest` always parses and validates JWT structure. Signature verification runs only when `callbacks.verifyJwt` is provided.

Public key resolution for verification:
1. `client_id` with `x509_hash:` prefix: requires `header.x5c`
2. `client_id` with `openid_federation:` prefix or no prefix: requires `header.trust_chain` and `header.kid`

```typescript
import { parseAuthorizeRequest } from "@pagopa/io-wallet-oid4vp";
import { IoWalletSdkConfig, ItWalletSpecsVersion } from "@pagopa/io-wallet-utils";

const config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const parsedRequest = await parseAuthorizeRequest({
  config,
  requestObjectJwt: requestData.requestObjectJwt,
  callbacks: {
    verifyJwt: myVerifyJwtCallback,
  },
});

console.log(parsedRequest.header.alg);
console.log(parsedRequest.payload.client_id);
```

### 3) Create encrypted authorization response (JARM)

```typescript
import { createAuthorizationResponse } from "@pagopa/io-wallet-oid4vp";

const { authorizationResponsePayload, jarm } = await createAuthorizationResponse({
  callbacks: {
    encryptJwe: myEncryptJweCallback,
    generateRandom: myGenerateRandomCallback,
  },
  requestObject: {
    client_id: parsedRequest.payload.client_id,
    client_metadata: parsedRequest.payload.client_metadata,
    nonce: parsedRequest.payload.nonce,
    state: parsedRequest.payload.state,
  },
  rpJwks: {
    jwks: rpMetadata.jwks,
    encrypted_response_enc_values_supported:
      rpMetadata.encrypted_response_enc_values_supported,
  },
  vp_token: myVpToken,
});

console.log(authorizationResponsePayload.state);
console.log(jarm.responseJwe); // Send this to response_uri
```

### 4) Send authorization response

```typescript
import { fetchAuthorizationResponse } from "@pagopa/io-wallet-oid4vp";

const responseResult = await fetchAuthorizationResponse({
  authorizationResponseJarm: jarm.responseJwe,
  callbacks: { fetch: globalThis.fetch },
  presentationResponseUri: parsedRequest.payload.response_uri,
});

console.log(responseResult.redirect_uri);
```

## API Reference

### `fetchAuthorizationRequest`

```typescript
export interface FetchAuthorizationRequestOptions {
  authorizeRequestUrl: string;
  callbacks: Pick<CallbackContext, "fetch">;
  walletMetadata?: {
    authorization_endpoint?: string;
    client_id_prefixes_supported?: string[];
    request_object_signing_alg_values_supported?: string[];
    response_modes_supported?: string[];
    response_types_supported?: string[];
    vp_formats_supported?: Record<string, unknown>;
  };
  walletNonce?: string;
}

export interface FetchAuthorizationRequestResult {
  parsedQrCode: {
    clientId: string;
    requestUri?: string;
    requestUriMethod?: "get" | "post";
  };
  requestObjectJwt: string;
  sendBy: "reference" | "value";
}
```

### `parseAuthorizeRequest`

```typescript
export interface ParseAuthorizeRequestOptions {
  callbacks?: Pick<CallbackContext, "verifyJwt">;
  config: IoWalletSdkConfig;
  requestObjectJwt: string;
}

export interface ParsedAuthorizeRequestResult {
  header: Openid4vpAuthorizationRequestHeader;
  payload: Openid4vpAuthorizationRequestPayload;
}
```

### `createAuthorizationResponse`

```typescript
export interface CreateAuthorizationResponseOptions {
  authorization_encrypted_response_alg?: string;
  authorization_encrypted_response_enc?: string;
  callbacks: Pick<CallbackContext, "encryptJwe" | "generateRandom">;
  requestObject: Pick<
    Openid4vpAuthorizationRequestPayload,
    "client_id" | "client_metadata" | "nonce" | "state"
  >;
  rpJwks: {
    encrypted_response_enc_values_supported?: string[];
  } & Pick<
    ItWalletCredentialVerifierMetadata | ItWalletCredentialVerifierMetadataV1_3,
    "jwks"
  >;
  vp_token: VpToken;
}

export interface CreateAuthorizationResponseResult {
  authorizationResponsePayload: Openid4vpAuthorizationResponse;
  jarm: {
    encryptionJwk: Jwk;
    responseJwe: string;
  };
}
```

### `fetchAuthorizationResponse`

```typescript
export interface FetchAuthorizationResponseOptions {
  authorizationResponseJarm: string;
  callbacks: Pick<CallbackContext, "fetch">;
  presentationResponseUri: string;
}
```

## Error Types

- `Oid4vpError`: base package error
- `ParseAuthorizeRequestError`: parse/verification errors in `parseAuthorizeRequest`
- `CreateAuthorizationResponseError`: authorization response creation errors
- `FetchAuthorizationResponseError`: errors when POSTing the response to `response_uri`
- `InvalidRequestUriMethodError`: invalid `request_uri_method` value
