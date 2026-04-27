# @pagopa/io-wallet-oid4vp

## 1.3.0

### Patch Changes

- 0decc23: refactor: remove nested barrel files to improve tree-shaking and avoid accidental circular dependencies
- Updated dependencies [c53d926]
- Updated dependencies [66e7f8b]
- Updated dependencies [0decc23]
  - @pagopa/io-wallet-oauth2@1.3.0
  - @pagopa/io-wallet-utils@1.3.0
  - @pagopa/io-wallet-oid-federation@1.3.0

## 1.2.1

### Patch Changes

- Updated dependencies [09a60bc]
  - @pagopa/io-wallet-oid-federation@1.2.1
  - @pagopa/io-wallet-oauth2@1.2.1
  - @pagopa/io-wallet-utils@1.2.1

## 1.2.0

### Minor Changes

- 32a8f92: feat: upgrade zod library to v4

### Patch Changes

- 586cb5e: fix: add local JWT signer header mapping aligned with IT Wallet spec
  refactor: ensuring compile-time enforcement in OID4VP createAuthorizationRequest of allowed signer types for each IT Wallet spec version
- Updated dependencies [32a8f92]
- Updated dependencies [586cb5e]
  - @pagopa/io-wallet-oid-federation@1.2.0
  - @pagopa/io-wallet-oauth2@1.2.0
  - @pagopa/io-wallet-utils@1.2.0

## 1.1.2

### Patch Changes

- Updated dependencies [a76b6ab]
  - @pagopa/io-wallet-oid-federation@1.1.2
  - @pagopa/io-wallet-oauth2@1.1.2
  - @pagopa/io-wallet-utils@1.1.2

## 1.1.1

### Patch Changes

- Updated dependencies [88300a3]
  - @pagopa/io-wallet-oid-federation@1.1.1
  - @pagopa/io-wallet-oauth2@1.1.1
  - @pagopa/io-wallet-utils@1.1.1

## 1.1.0

### Minor Changes

- 8707488: feat: add createAuthorizationRequest utility function
- 6e681d7: feat: add oid4vp parseAuthorizationResponse utility function

### Patch Changes

- Updated dependencies [8278fb5]
- Updated dependencies [e4eca58]
- Updated dependencies [1eda2cf]
  - @pagopa/io-wallet-oauth2@1.1.0
  - @pagopa/io-wallet-utils@1.1.0
  - @pagopa/io-wallet-oid-federation@1.1.0

## 1.0.0

### Patch Changes

- Updated dependencies [aa144b1]
- Updated dependencies [5b625e6]
- Updated dependencies [752dbb0]
- Updated dependencies [6e19722]
- Updated dependencies [086c33e]
- Updated dependencies [fcf91a5]
- Updated dependencies [e450ab5]
- Updated dependencies [259f790]
  - @pagopa/io-wallet-oauth2@1.0.0
  - @pagopa/io-wallet-utils@1.0.0
  - @pagopa/io-wallet-oid-federation@1.0.0

## 0.7.7

### Patch Changes

- Updated dependencies [77ee405]
  - @pagopa/io-wallet-oid-federation@0.7.7
  - @pagopa/io-wallet-utils@0.7.7

## 0.7.6

### Patch Changes

- c5c5737: Fix NPM publish workflow
- Updated dependencies [c5c5737]
  - @pagopa/io-wallet-oid-federation@0.7.6
  - @pagopa/io-wallet-utils@0.7.6

## 0.7.5

### Patch Changes

- @pagopa/io-wallet-oid-federation@0.7.5
- @pagopa/io-wallet-utils@0.7.5

## 0.7.4

### Patch Changes

- 8c40305: Expose jwt header in parseAuthorizeRequest
- 1a692a8: fix redirect_uri schema to be optional
  - @pagopa/io-wallet-oid-federation@0.7.4
  - @pagopa/io-wallet-utils@0.7.4

## 0.7.3

### Patch Changes

- a979b82: Make signer optional in CreateAuthorizationResponseOptions
  - @pagopa/io-wallet-oid-federation@0.7.3
  - @pagopa/io-wallet-utils@0.7.3

## 0.7.2

### Patch Changes

- 8d383be: Improve error messaging and enhance module exports
  - @pagopa/io-wallet-oid-federation@0.7.2
  - @pagopa/io-wallet-utils@0.7.2

## 0.7.1

### Patch Changes

- 5d2e6df: Implement client_id prefix extraction and enhance Request object handling
  - @pagopa/io-wallet-oid-federation@0.7.1
  - @pagopa/io-wallet-utils@0.7.1

## 0.7.0

### Minor Changes

- f6d86e5: feat(oid4vp): [WLEO-652] add fetchAuthorizationRequest utility

### Patch Changes

- b84d8c2: Align Request Object with IT specs 1.3.0
  - @pagopa/io-wallet-oid-federation@0.7.0
  - @pagopa/io-wallet-utils@0.7.0

## 0.6.2

### Patch Changes

- @pagopa/io-wallet-oid-federation@0.6.2
- @pagopa/io-wallet-utils@0.6.2

## 0.6.1

### Patch Changes

- aaae8bb: Add OAuth authorization request JWT header validation
- Updated dependencies [cead548]
  - @pagopa/io-wallet-oid-federation@0.6.1
  - @pagopa/io-wallet-utils@0.6.1

## 0.6.0

### Patch Changes

- Updated dependencies [b2a7475]
  - @pagopa/io-wallet-utils@0.6.0
  - @pagopa/io-wallet-oid-federation@0.6.0

## 0.5.1

### Patch Changes

- @pagopa/io-wallet-oid-federation@0.5.1

## 0.5.0

### Patch Changes

- b08028e: Add type modifier to type-only exports in oauth2 package
- Updated dependencies [8ecf5ec]
  - @pagopa/io-wallet-oid-federation@0.5.0

## 0.4.2

### Patch Changes

- 936caa4: Fix TypeScript type resolution by correcting package.json exports

## 0.4.1

### Patch Changes

- 7356f00: Fix publish public to npm

## 0.4.0
