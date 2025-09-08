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
import { ItWalletProvider } from '@pagopa/io-wallet-oid4vci';

// Initialize the provider with required options
const walletProvider = new ItWalletProvider({
  // Openid4vciWalletProviderOptions configuration
  // Add your specific configuration here
});
```

### Creating a Wallet Attestation

Create wallet attestations required during the OID4VCI flow:

```typescript
import { ItWalletProvider, WalletAttestationOptions } from '@pagopa/io-wallet-oid4vci';

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

## API Reference

`ItWalletProvider`: A class that extends Openid4vciWalletProvider to provide specialized methods for the Italian Wallet ecosystem.