# IO Wallet SDK

[![CI](https://github.com/pagopa/io-wallet-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/pagopa/io-wallet-sdk/actions)
[![npm](https://img.shields.io/npm/v/@pagopa/io-wallet-utils?label=latest)](https://www.npmjs.com/search?q=%40pagopa%2Fio-wallet)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

A comprehensive TypeScript library for building applications that integrate with **Italy's national digital identity wallet**. 🇮🇹

This SDK provides all the necessary tools to handle Verifiable Credentials and secure interactions according to the official Italian specifications, which are based on **OpenID for Verifiable Credentials (OpenID4VC)** and **OAuth 2.0** standards. It builds upon the foundation of the [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) library from the OpenWallet Foundation, extending it to meet the specific requirements of the Italian digital ecosystem.

The project is structured as a monorepo using `pnpm` and is designed to be environment-agnostic (Node.js, Browser, React Native), allowing you to build services for Relying Parties, Issuers, and Wallets.

## Key Features

- **Full IT-Wallet Compliance**: Implements the specific profiles and flows required by the official [IT Wallet specifications](https://italia.github.io/eid-wallet-it-docs/en/), supporting versions **V1.0**, **V1.3**, and **V1.4**.
- **Modern & Secure**: Built with TypeScript and includes support for modern OAuth 2.0 extensions like `PAR`, `DPoP`, and `PKCE`.
- **Modular Architecture**: The core logic is split into scoped packages, so you only use what you need.
- **Crypto Agnostic**: Does not impose a specific cryptographic library.

## Packages

This SDK is a monorepo containing the following packages:

| Package                                | Description                                                                                                                                               |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`@pagopa/io-wallet-oauth2`**         | Implements core OAuth 2.0 flows and security extensions (PAR, DPoP, PKCE, JARM) required for secure interactions.                                        |
| **`@pagopa/io-wallet-oid-federation`** | Handles entity discovery and trust chain resolution within the Italian Federation, ensuring all actors are trusted and valid.                              |
| **`@pagopa/io-wallet-oid4vci`**        | Manages **Verifiable Credential Issuance** flows. Use this to build Issuer services for credentials like the `mso_mdoc` (e.g., Digital Driver's License). |
| **`@pagopa/io-wallet-oid4vp`**         | Manages **Verifiable Presentation** flows. Use this to build Relying Party services that request and verify user credentials from the IT-Wallet.          |
| **`@pagopa/io-wallet-utils`**          | Shared types, configuration (`IoWalletSdkConfig`, `ItWalletSpecsVersion`), and utilities used across all packages.                                        |

## Which packages do I need?

The IT-Wallet ecosystem has three distinct actor roles. Install only the packages relevant to your use case.

| Role | Description | Packages |
| ---- | ----------- | -------- |
| **Relying Party** (Verifier) | Requests and verifies credentials from a user's wallet | `@pagopa/io-wallet-oid4vp`, `@pagopa/io-wallet-oid-federation` |
| **Credential Issuer** | Issues Verifiable Credentials to a wallet | `@pagopa/io-wallet-oid4vci`, `@pagopa/io-wallet-oid-federation` |
| **Wallet Provider** | Manages wallet instance lifecycle and attestations | `@pagopa/io-wallet-oid4vci`, `@pagopa/io-wallet-oauth2`, `@pagopa/io-wallet-oid-federation` |

All roles require `@pagopa/io-wallet-utils` for shared configuration types.

## Installation

Install the packages for your role:

```bash
# Relying Party (Verifier)
pnpm add @pagopa/io-wallet-oid4vp @pagopa/io-wallet-oid-federation @pagopa/io-wallet-utils

# Credential Issuer
pnpm add @pagopa/io-wallet-oid4vci @pagopa/io-wallet-oid-federation @pagopa/io-wallet-utils

# Wallet Provider
pnpm add @pagopa/io-wallet-oid4vci @pagopa/io-wallet-oauth2 @pagopa/io-wallet-oid-federation @pagopa/io-wallet-utils
```

## Callback Pattern

This SDK is **crypto-agnostic and environment-agnostic**. Instead of bundling a specific cryptographic library or HTTP client, every function that needs to sign JWTs, hash data, or make HTTP requests accepts a `callbacks` object where you provide your own implementations.

This makes the SDK compatible with Node.js, browsers, and React Native without modification.

```typescript
import { createTokenDPoP } from '@pagopa/io-wallet-oauth2';

const result = await createTokenDPoP({
  // Provide your own implementations for cryptographic operations
  callbacks: {
    signJwt: async (signer, { header, payload }) => {
      // Use any JWT library or hardware key (e.g. node-jose, jose, HSM)
      return {
        jwt: myJwtLibrary.sign(header, payload, myPrivateKey),
        signerJwk: myPublicJwk,
      };
    },
    hash: async (data, algorithm) => {
      // Use any hash implementation (e.g. SubtleCrypto, node:crypto)
      const digest = await crypto.subtle.digest(algorithm, data);
      return new Uint8Array(digest);
    },
    generateRandom: async (byteLength) => {
      // Use any CSPRNG available in your environment
      return crypto.getRandomValues(new Uint8Array(byteLength));
    },
  },
  signer: { method: 'jwk', publicJwk: myPublicJwk, alg: 'ES256' },
  tokenRequest: { method: 'POST', url: 'https://issuer.example.com/token' },
});
```

Each function documents exactly which callbacks it requires via TypeScript's `Pick<CallbackContext, ...>`, so you only implement what is needed.

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

| Spec Version | Status |
| ------------ | ------ |
| V1.0         | Supported |
| V1.3         | Supported |
| V1.4         | Supported |

```typescript
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';

const config = new IoWalletSdkConfig({
  itWalletSpecsVersion: ItWalletSpecsVersion.V1_4 // or V1_0, V1_3
});
```

## 🧭 Contribute

For internal development conventions and contribution guidelines, see [CONTRIBUTING.md](CONTRIBUTING.md).
