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

## Basic Usage

```typescript
import {
  createCredentialRequest,
  fetchMetadata,
} from "@pagopa/io-wallet-oid4vci";
import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

const config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
});

const metadata = await fetchMetadata({
  callbacks: { fetch, verifyJwt },
  config,
  credentialIssuerUrl: "https://issuer.example.it",
});

const request = await createCredentialRequest({
  callbacks: { hash, signJwt },
  clientId: "wallet-client-id",
  config,
  credential_identifier: "pid",
  issuerIdentifier: "https://issuer.example.it",
  keyAttestation,
  nonce: "c_nonce",
  signers: [signer],
});
```

The package uses callback injection for HTTP, signing, hashing, verification,
and encryption so SDK consumers can provide platform-specific implementations.
