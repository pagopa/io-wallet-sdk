# IO Wallet SDK

A comprehensive TypeScript library for building applications that integrate with **Italy's national digital identity wallet**. 🇮🇹

This SDK provides all the necessary tools to handle Verifiable Credentials and secure interactions according to the official Italian specifications, which are based on **OpenID for Verifiable Credentials (OpenID4VC)** and **OAuth 2.0** standards. It builds upon the foundation of the [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) library from the OpenWallet Foundation, extending it to meet the specific requirements of the Italian digital ecosystem.

The project is structured as a monorepo using `pnpm` and is designed to be environment-agnostic (Node.js, Browser, React Native), allowing you to build services for Relying Parties, Issuers, and Wallets.

## Key Features

- **Full IT-Wallet Compliance**: Implements the specific profiles and flows required by the official [IT Wallet specifications](https://italia.github.io/eid-wallet-it-docs/releases/1.0.2/en/), currently 1.0.2 version.
- **Modern & Secure**: Built with TypeScript and includes support for modern OAuth 2.0 extensions like `PAR`, `DPoP`, and `PKCE`.
- **Modular Architecture**: The core logic is split into scoped packages, so you only use what you need.
- **Crypto Agnostic**: Does not impose a specific cryptographic library.

## Packages

This SDK is a monorepo containing the following packages:

| Package                                | Description                                                                                                                                               |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`@pagopa/io-wallet-oauth2`**         | Implements core OAuth 2.0 flows and security extensions (PAR, DPoP, PKCE, JARM) required for secure interactions.                                         |
| **`@pagopa/io-wallet-oid-federation`** | Handles entity discovery and trust chain resolution within the Italian Federation, ensuring all actors are trusted and valid. 🛡️                          |
| **`@pagopa/io-wallet-oid4vci`**        | Manages **Verifiable Credential Issuance** flows. Use this to build Issuer services for credentials like the `mso_mdoc` (e.g., Digital Driver's License). |
| **`@pagopa/io-wallet-oid4vp`**         | Manages **Verifiable Presentation** flows. Use this to build Relying Party services that request and verify user credentials from the IT-Wallet. ✅       |

## Installation

To get started, install the packages you need for your project using `pnpm`.

```bash
# To build a Relying Party (Verifier)
pnpm add @it-wallet-sdk/oid4vp @it-wallet-sdk/oid-federation

# To build an Issuer
pnpm add @it-wallet-sdk/oid4vci @it-wallet-sdk/oid-federation
```

## Development

To set up the repository for local development:

1. Clone the repository :

   ```bash
   git clone https://github.com/pagopa/io-wallet-sdk.git
   cd io-wallet-sdk
   ```

2. Install dependencies:

   ```bash
   pnpm install
   ```

3. Build all packages:

   ```bash
   pnpm run build
   ```

## Version Configuration

The SDK supports multiple versions of the Italian Wallet technical specifications. You must configure the version in some methods using `IoWalletSdkConfig`.

```typescript
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';

// Create a configuration for IT-Wallet v1.0
const configV1_0 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_0
});

// Create a configuration for IT-Wallet v1.3
const configV1_3 = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_3
});
```

## 🧭 Contribute

For internal development conventions and contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).
