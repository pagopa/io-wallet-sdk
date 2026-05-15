## @pagopa/io-wallet-oid-federation

OpenID Federation helpers and schemas for the IT-Wallet trust infrastructure,
including entity configuration claims, entity statement claims, metadata schemas,
metadata policy operators, JSON Web Key utilities, and trust-chain validation.

Detailed function documentation is maintained in source JSDoc and surfaced by
TypeScript declarations and IDEs.

## Installation

```bash
pnpm add @pagopa/io-wallet-oid-federation
```

## Basic Usage

```typescript
import { createItWalletEntityConfiguration } from "@pagopa/io-wallet-oid-federation";

const entityConfigurationJwt = await createItWalletEntityConfiguration({
  claims: {
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    iss: "https://entity.example.it",
    jwks,
    sub: "https://entity.example.it",
  },
  header: {
    alg: "ES256",
    kid: "signing-key-1",
    typ: "entity-statement+jwt",
  },
  signJwtCallback,
});
```

Use this package with the OAuth2, OID4VCI, and OID4VP packages whenever a flow
requires federation metadata, entity statements, or trust-chain validation.
