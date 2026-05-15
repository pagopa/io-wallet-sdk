## @pagopa/io-wallet-oauth2

OAuth 2.0 helpers for IT-Wallet flows, including Pushed Authorization Requests,
PKCE, DPoP, JAR/JARM utilities, access-token handling, wallet/client
attestation helpers, and MRTD proof-of-possession support.

Detailed function documentation is maintained in source JSDoc and surfaced by
TypeScript declarations and IDEs.

## Installation

```bash
pnpm add @pagopa/io-wallet-oauth2
```

## Basic Usage

```typescript
import { createPkce, createTokenDPoP } from "@pagopa/io-wallet-oauth2";

const pkce = await createPkce({
  callbacks: { generateRandom, hash },
});

const dpop = await createTokenDPoP({
  callbacks: { generateRandom, hash, signJwt },
  signer,
  tokenRequest: {
    method: "POST",
    url: "https://issuer.example.it/token",
  },
});
```

The package is environment-agnostic: provide cryptographic and HTTP operations
through callbacks instead of relying on runtime globals.
