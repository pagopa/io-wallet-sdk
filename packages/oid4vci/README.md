## @pagopa/io-wallet-oid4vci

This package provides functionalities to manage the **OpenID for Verifiable Credentials Issuance (OID4VCI)** protocol flow, specifically tailored for the Italian Wallet ecosystem. It simplifies the creation of wallet attestations required during the credential issuance process.

## Installation

To install the package, use your preferred package manager:

```bash
# Using pnpm
pnpm add @pagopa/io-wallet-oid4vci

# Using yarn
yarn add @pagopa/io-wallet-oid4vci

## Usage

### Wallet Provider

```typescript
import { WalletProvider } from '@pagopa/io-wallet-oid4vci';

// Initialize the provider with required options
const walletProvider = new WalletProvider({
  // Openid4vciWalletProviderOptions configuration
  // Add your specific configuration here
});
```

### Creating a Wallet Attestation

Create wallet attestations required during the OID4VCI flow:

```typescript
import { WalletProvider, WalletAttestationOptions } from '@pagopa/io-wallet-oid4vci';

// Create wallet attestation
const attestationOptions: WalletAttestationOptions = {
  issuer: "https://wallet-provider.example.com",
  dpopJwkPublic: {
    // JWK public key for DPoP binding
    kid: "dpop-key-id",
    kty: "EC",
    crv: "P-256",
    x: "...",
    y: "..."
  },
  signer: {
    walletProviderJwkPublicKid: "wallet-provider-key-id",
    trustChain: [
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9...", // Trust anchor JWT
      // Additional trust chain JWTs
    ]
  },
  walletName: "My Italian Wallet", // Optional
  walletLink: "https://mywalletapp.com", // Optional
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) // Optional, defaults to 60 days
};

const attestationJwt = await walletProvider.createItWalletAttestationJwt(attestationOptions);
```

The wallet attestation JWT can then be used in the OID4VCI protocol flow to prove the wallet's identity and key possession.

### Creating Credential Requests

The credential request format varies based on the configured IT-Wallet specification version:

#### IT-Wallet v1.0

```typescript
import { 
  IoWalletSdkConfig, 
  ItWalletSpecsVersion,
  createCredentialRequest 
} from '@pagopa/io-wallet-oid4vci';

const config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0
});

const request = await createCredentialRequest({
  config,
  callbacks: { signJwt: mySignJwtCallback },
  clientId: "my-client-id",
  credential_identifier: "UniversityDegree",
  issuerIdentifier: "https://issuer.example.com",
  nonce: "c_nonce_value",
  signer: myJwtSigner
});

// Returns: { 
//   credential_identifier: "UniversityDegree", 
//   proof: { jwt: "...", proof_type: "jwt" } 
// }
```

#### IT-Wallet v1.3

```typescript
import { 
  IoWalletSdkConfig, 
  ItWalletSpecsVersion,
  createCredentialRequest 
} from '@pagopa/io-wallet-oid4vci';

const config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3
});

const request = await createCredentialRequest({
  config,
  callbacks: { signJwt: mySignJwtCallback },
  clientId: "my-client-id",
  credential_identifier: "education_degree_unibo_2017_l31_informatica",
  issuerIdentifier: "https://issuer.example.com",
  keyAttestation: "eyJhbGciOiJFUzI1NiJ9...", // Required in v1.3
  nonce: "c_nonce_value",
  signer: myJwtSigner
});

// Returns: { 
//   credential_identifier: "education_degree_unibo_2017_l31_informatica", 
//   proofs: { jwt: ["..."] } 
// }
```

### `completeAuthorization`

```typescript
import { CompleteAuthorizationOptions, completeAuthorization } from "@pagopa/io-wallet-oid4ci"

//Obtain a response uri from an OID4VP authorization flow
const response_uri = "https://response.example.com"

//Build the parameters
const options : CompleteAuthorizationOptions = {
  fetch,
  response_uri
}

/**
 * Result is in the following form:
 * {
 *    jwt : "ey...",
 *    decodedJwt : {
 *      header : {
 *        alg : "ES256",
 *        ...
 *      },
 *      payload : {
 *        iss : "https://iss.example.com",
 *        state : "EXAMPLE_STATE",
 *        code : "ACCESS_CODE"
 *      },
 *      signature : "..."
 *    }
 * }
 */
const result = await completeAuthorization(options)
```

### `verifyAuthorizationResponse`

```typescript
import {verifyAuthorizationResponse, VerifyAuthorizationResponseOptions} from "@pagopa/io-wallet-oid4vci"

// Obtain an authorizationResponse
const response = {
  code : "TEST_CODE",
  iss : "http://iss.example.com",
  state : "TEST_STATE"
}

//Retrieve the expected issuer and state sent at the start of the authorization flow
const EXPECTED_ISS = "http://iss.example.com"
const EXPECTED_STATE = "TEST_STATE"

//Check if they are correct
verifyAuthorizationResponse({
  authorizationResponse : response,
  iss : EXPECTED_ISS,
  state: EXPECTED_STATE
} satisfies VerifyAuthorizationResponseOptions)
```

### `verifyAuthorizationResponseFormPostJWT`

```typescript
import {verifyAuthorizationResponseFormPostJWT, VerifyAuthorizationResponseFormPostJWTOptions} from "@pagopa/io-wallet-oid4vci"
import { JwtSignerJwk } from "@pagopa/io-wallet-oauth2"

// Obtain a decoded jwt cotaining the authoization response...
const decodedJwt = {
  header : {
    alg : "ES256",
    ...
  },
  payload :{
    code : "TEST_CODE",
    iss : "http://iss.example.com",
    state : "TEST_STATE"
  },
  signature : "..."
}

//...and its compact form
const jwt = "ey..."

//Retrieve the signer's public key and build the corrsponing Signer object
const signer : JwtSignerJwk = {
  mehtod: "jwk",
  alg : "ES256",
  publicJwk : {
    kty : "EC",
    ...
  }
}

//Retrieve the expected issuer and state sent at the start of the authorization flow
const EXPECTED_ISS = "http://iss.example.com"
const EXPECTED_STATE = "TEST_STATE"

//Check the iss and state fields match the expected values and verify jwt signature
verifyAuthorizationResponseFormPostJWT({
  authorizationResponseCompact : jwt,
  authorizationResponseDecoded : decodedJwt,
  callbacks : {
    verifyJwt : (signer, {header, payload, compact}) => {
      ... //Signature verification
    }
  }
  iss : EXPECTED_ISS,
  signer,
  state: EXPECTED_STATE
} satisfies VerifyAuthorizationResponseFormPostJWTOptions)
```

### `sendAuthorizationResponseAndExtractCode`

```typescript
import {sendAuthorizationResponseAndExtractCode, SendAuthorizationResponseAndExtractCodeOptions} from "@pagopa/io-wallet-oid4vci"

//Retrieve the necessary parameters
const baseOptions: SendAuthorizationResponseAndExtractCodeOptions = {
  //Signature JARM
  authorizationResponseJarm: "...",
  callbacks: {
    fetch,
    verifyJwt: (signer, {header, payload, compact}) => {
      ... //verify signature
    },
  },
  //Issuance session's credential issuer
  iss: "http://iss.example.com",
  presentationResponseUri: "http://response.oidvp.example.com",
  //Retrieve the form_post.jwt response's corresponsing public key and create its corresponding signer
  signer: {
    alg: "ES256",
    method: "jwk",
    publicJwk: {
      kty: "EC",
    },
  },
  //The authorization state
  state: "TEST_STATE",
};

//Obtain the authorization code

const {code, iss, state} = await sendAuthorizationResponseAndExtractCode(options)
```

## API Reference

`WalletProvider`: A class that extends Openid4vciWalletProvider to provide specialized methods for the Italian Wallet ecosystem.


`completeAuthorization` : Method that completes the `form_post.jwt` based authorization process for credentials issuance following the ITWallet
                          specification by retrieving the form from the provided uri, extracting and parsing the contained JWT and verifying the
                          `iss` and `state` fields match the authorization session's expected values.


`verifyAuthorizationResponse` : Utility that verifies if the returned Authorization Response's 
                                                      `iss` and `state` field match the Authorization Session ones

`verifyAuthorizationResponseFormPostJWT` : Wrapper of `verifyAuthorizationResponse` that verifies the signature of the JWT containing
                                           the authorization response and extracts the Authorization Response payload

`sendAuthorizationResponseAndExtractCode` : Convenience method that combines `completeAuthorization`, 
                                            oid4vp package's `fetchAuthorizationResponse` and `verifyAuthorizationResponseFormPostJWT` 
                                            to retrieve the access code starting from the authorization response and the response uri

## Errors

```typescript
export class Oid4vciError extends Error {
  constructor(
    message: string,
    public readonly statusCode?: number,
  ) {
    super(message);
    this.name = "Oid4vciError";
  }
}
```
Generic error thrown on Oid4vci operations

Error thrown in case the DPoP key passed to the `WalletProvider.createItWalletAttestationJwt` method doesn't contain a kid
```typescript
export class WalletProviderError extends Oid {
  constructor(
    message: string,
    public readonly originalError?: unknown,
  ) {
    super(message);
    this.name = "WalletProviderError";
  }
}
```
