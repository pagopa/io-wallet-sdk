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

## 📝 Naming Conventions
- **Object and method names must not include the prefix `ItWallet`.**  
  Use descriptive, context-appropriate names instead.  
- Keep naming consistent across all packages.

---
