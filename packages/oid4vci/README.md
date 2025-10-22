## @pagopa/io-wallet-oid4vci

This package provides functionalities to manage the **OpenID for Verifiable Credentials Issuance (OID4VCI)** protocol flow, specifically tailored for the Italian Wallet ecosystem. It simplifies the creation of wallet attestations required during the credential issuance process.

## Installation

To install the package, use your preferred package manager:

```bash
# Using pnpm
pnpm add @pagopa/io-wallet-oid4vci

# Using yarn
yarn add @pagopa/io-wallet-oid4vci
```

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
    y: "...",
  },
  signer: {
    walletProviderJwkPublicKid: "wallet-provider-key-id",
    trustChain: [
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9...", // Trust anchor JWT
      // Additional trust chain JWTs
    ],
  },
  walletName: "My Italian Wallet", // Optional
  walletLink: "https://mywalletapp.com", // Optional
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // Optional, defaults to 60 days
};

const attestationJwt =
  await walletProvider.createItWalletAttestationJwt(attestationOptions);
```

The wallet attestation JWT can then be used in the OID4VCI protocol flow to prove the wallet's identity and key possession.

## API Reference

`WalletProvider`: A class that extends Openid4vciWalletProvider to provide specialized methods for the Italian Wallet ecosystem.

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
