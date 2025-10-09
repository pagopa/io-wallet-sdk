# IO Wallet SDK

A comprehensive TypeScript library for building applications that integrate with **Italy's national digital identity wallet**. 🇮🇹

This SDK provides all the necessary tools to handle Verifiable Credentials and secure interactions according to the official Italian specifications, which are based on **OpenID for Verifiable Credentials (OpenID4VC)** and **OAuth 2.0** standards. It builds upon the foundation of the [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) library from the OpenWallet Foundation, extending it to meet the specific requirements of the Italian digital ecosystem.

The project is structured as a monorepo using `pnpm` and is designed to be environment-agnostic (Node.js, Browser, React Native), allowing you to build services for Relying Parties, Issuers, and Wallets.

## Key Features

- **Full IT-Wallet Compliance**: Implements the specific profiles and flows required by the official [IT Wallet specifications](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/).
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

## 🧭 Development Guidelines

This SDK follows a set of common conventions to ensure consistency, maintainability, and interoperability across all packages in the monorepo.

### 📡 Method Requests
- Each package provides **both options**:
  - A **complete `fetch` implementation** that performs the request and parses the response.  
  - **Helper methods** to build request bodies and **exposed response schemas**, allowing consumers to handle network calls manually if preferred.  
- This gives consumers flexibility to either rely on the SDK’s built-in request flow or integrate the lower-level utilities into their own infrastructure.

### ⚙️ Error Handling
- **Common errors** shared across packages (e.g., `JsonParseError`, `ValidationError`) are defined in the shared `@io-wallet/utils` package.  
- **Package-specific errors** should:
  - Extend a **generic error** for that package (e.g., `Oauth2Error`).
  - Optionally include **granular errors per method** (e.g., `AuthorizationRequestParsingError`).
  - Be collected in a single `src/error.ts` file per package.  
- Each method should include a **global `try/catch` block** and rethrow a generic error (from `@io-wallet/utils`) or a granular error (e.g., `AuthorizationRequestParsingError`) for unhandled exceptions.

### 🔐 Cryptographic Variables
- Cryptographic values (e.g., `state`, `jti`) must be:
  - **Randomly generated** using the shared `generateRandom` callback, or  
  - **Passed externally** by the consumer.  

### 🧩 Dependencies
- All packages must share the **same version** of common dependencies (e.g., `@openid4vc/oauth2`), managed via **pnpm catalog**.

### 📦 Public Exports
- Objects from third-party libraries (e.g., `Jwt`, `SignJwtCallback` from `openid4vc`) that are needed by consumers should be **re-exported from `io-wallet-sdk`** to ensure a unified public API surface.

### 📝 Naming Conventions
- **Object and method names must not include the prefix `ItWallet`.**  
  Use clear, context-relevant naming instead.


## License

This project is licensed under the MIT License.
