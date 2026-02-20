# @pagopa/io-wallet-oauth2

## 1.0.0

### Minor Changes

- aa144b1: add client authentications utility functions
- 752dbb0: Add parseAuthorizationRequest and parsePushedAuthorizationRequest
- 6e19722: Add verifyPushedAuthorizationRequest and verifyAuthorizationRequest features
- 086c33e: add isClientAttestationSupported utility function
- fcf91a5: add parseAccessTokenRequest utility
- 259f790: add verifyAuthorizationCodeTokenRequest utility function

### Patch Changes

- 5b625e6: fix: refactoring WalletProvider and remove unused config option from createWalletAttestationJwt methods in v1.0 and v1.3 branches
- Updated dependencies [752dbb0]
- Updated dependencies [e450ab5]
  - @pagopa/io-wallet-utils@1.0.0

## 0.7.7

### Patch Changes

- @pagopa/io-wallet-utils@0.7.7

## 0.7.6

### Patch Changes

- c5c5737: Fix NPM publish workflow
- Updated dependencies [c5c5737]
  - @pagopa/io-wallet-utils@0.7.6

## 0.7.5

### Patch Changes

- @pagopa/io-wallet-utils@0.7.5

## 0.7.4

### Patch Changes

- f448bc5: Add pkceCodeVerifier to createPushedAuthorizationRequest response
  - @pagopa/io-wallet-utils@0.7.4

## 0.7.3

### Patch Changes

- @pagopa/io-wallet-utils@0.7.3

## 0.7.2

### Patch Changes

- 1f00123: Add dPoP support to FetchTokenResponseOptions
  - @pagopa/io-wallet-utils@0.7.2

## 0.7.1

### Patch Changes

- @pagopa/io-wallet-utils@0.7.1

## 0.7.0

### Patch Changes

- @pagopa/io-wallet-utils@0.7.0

## 0.6.2

### Patch Changes

- e0af6dc: Export JWE encryption types from oauth2 package
  - @pagopa/io-wallet-utils@0.6.2

## 0.6.1

### Patch Changes

- b2fc74d: fix: Make authorization_details and scope optional with validation
  - @pagopa/io-wallet-utils@0.6.1

## 0.6.0

### Minor Changes

- b2a7475: Add credential request implementation

### Patch Changes

- Updated dependencies [b2a7475]
  - @pagopa/io-wallet-utils@0.6.0

## 0.5.1

### Patch Changes

- c9e7651: Fix: client_id query param in PAR request
  - @pagopa/io-wallet-utils@0.5.1

## 0.5.0

### Minor Changes

- a673538: Add access token request and response handling with DPoP support
- 6331820: Create dpop with access token

### Patch Changes

- b08028e: Add type modifier to type-only exports in oauth2 package
  - @pagopa/io-wallet-utils@0.5.0

## 0.4.2

### Patch Changes

- 936caa4: Fix TypeScript type resolution by correcting package.json exports
- Updated dependencies [936caa4]
  - @pagopa/io-wallet-utils@0.4.2

## 0.4.1

### Patch Changes

- 7356f00: Fix publish public to npm
- Updated dependencies [7356f00]
  - @pagopa/io-wallet-utils@0.4.1

## 0.4.0

### Minor Changes

- 1d371c2: Added createClientAttestationPopJwt that generates a PoP JWT bound to a client attestation

### Patch Changes

- @pagopa/io-wallet-utils@0.4.0
