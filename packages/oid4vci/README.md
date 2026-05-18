## @pagopa/io-wallet-oid4vci

OpenID4VCI helpers for IT-Wallet credential issuance flows, including metadata
discovery, credential-offer parsing, authorization completion, credential
request parsing/verification, credential response creation, and wallet-provider
attestation utilities.

Detailed function documentation is maintained in source JSDoc and surfaced by
TypeScript declarations and IDEs.

## Installation

```bash
pnpm add @pagopa/io-wallet-oid4vci
```

The package uses callback injection for HTTP, signing, hashing, verification,
and encryption so SDK consumers can provide platform-specific implementations.
