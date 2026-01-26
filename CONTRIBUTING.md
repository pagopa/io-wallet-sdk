# 🧩 SDK Development Guidelines

This document defines the internal conventions and technical standards for contributing to the SDK.  
All packages in the monorepo should follow these rules to maintain consistency, reliability, and code quality.

---

## 📡 Network Requests
Each package should expose **two complementary levels of abstraction**:

1. **High-level implementation:**  
   - Includes the `fetch` call to the endpoint.  
   - Handles the full request lifecycle and parses the response.  
   - Returns typed, ready-to-use data objects.

2. **Low-level utilities:**  
   - Helper methods to **build request bodies** and **exposed response schemas**.  
   - Useful when consumers need to handle network requests manually or integrate with existing infrastructure.

This approach gives consumers full flexibility — they can either use the built-in `fetch` or manage the HTTP logic themselves.

---

## ⚙️ Error Handling
- **Common errors** You can use one of `@openid4vc/utils` (e.g., `JsonParseError`, `ValidationError`) or you can define in the shared `@io-wallet/utils` package.  
- **Package-specific errors** should:
  - Extend a generic base error for that package (e.g., `Oauth2Error`).  
  - Optionally define **granular errors per method** (e.g., `AuthorizationRequestParsingError`).  
  - Be grouped in a single `error.ts` file per package.  
- Each method should include a **global `try/catch` block** and rethrow a generic error (from `@io-wallet/utils`) or a granular error (e.g., `AuthorizationRequestParsingError`) for unhandled exceptions.

---

## 🔐 Cryptographic Variables
- Cryptographic values (e.g., `state`, `jti`) must be:
  - **Randomly generated** using the shared `generateRandom` callback, or  
  - **Passed externally** by the consumer.  

---

## 🧱 Dependencies
- All packages must use **the same version** of shared dependencies (e.g., `@openid4vc/oauth2`).  
- Version alignment is managed via the **pnpm catalog**.  
- Do not install duplicate or mismatched versions across packages.

---

## 📦 Public Exports
- Objects from third-party libraries (e.g., `Jwt`, `SignJwtCallback` from `openid4vc`) that are needed by consumers should be **re-exported from `io-wallet-sdk`**.  
- This ensures a **consistent public API surface** across the SDK.

---

## � Multi-Version Support
The SDK supports multiple versions of the Italian Wallet specifications simultaneously. Follow these guidelines when implementing version-specific features:

### Directory Structure
- Create version-specific subdirectories: `v1.0/`, `v1.3/`, etc.
- Each version directory contains:
  - Implementation files (e.g., `create-feature.ts`)
  - Zod schemas (prefixed with `z-`, e.g., `z-credential.ts`)
  - Test files under `__tests__/`

### Version Router Pattern
- **Top-level router**: Create a main function with TypeScript overloads
- **Type safety**: Use discriminated union types for version-specific options
- **Runtime validation**: Validate version-specific constraints (e.g., required parameters)
- **Exhaustiveness**: Always include a `default` case that throws `ItWalletSpecsVersionError`

### Type Definitions
- **Base options**: Define shared options in `types.ts`
- **Version-specific options**: Extend base with version-specific fields
- **Return types**: Create separate types for each version's response

### When to Add a New Version
- **New specification release**: Italian Wallet publishes a new major/minor version
- **Breaking changes**: Protocol structure changes (e.g., `proof` → `proofs`)
- **New required fields**: Version requires parameters not in previous versions

### When NOT to Version
- **Backward-compatible additions**: Add to existing implementation
- **Bug fixes**: Apply to all affected versions
- **Clarifications**: Update documentation, not code structure

---

## 📝 Naming Conventions
- **Object and method names must not include the prefix `ItWallet`.**  
  Use descriptive, context-appropriate names instead.  
- Keep naming consistent across all packages.

---
