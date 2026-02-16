# AGENTS.md

This file provides guidance to coding agents when working with code in this repository.

## Overview

IO Wallet SDK is a TypeScript monorepo implementing Italy's national digital identity wallet specifications (IT-Wallet v1.0). It provides OpenID4VC-compliant implementations for credential issuance and presentation flows according to Italian Federation requirements.

The SDK is built on top of [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) from the OpenWallet Foundation, extending it with Italian-specific profiles and requirements.

## Project Structure

This is a pnpm monorepo with the following packages under `packages/`:

- **oauth2**: Core OAuth 2.0 flows with Italian extensions (PAR, DPoP, PKCE, JARM)
- **oid4vci**: Credential Issuance flows (Issuer-side implementation)
- **oid4vp**: Credential Presentation flows (Verifier/Relying Party implementation)
- **oid-federation**: Italian Federation trust chain resolution and entity discovery
- **utils**: Shared utilities and re-exports from upstream libraries

### Package Dependencies

Packages use workspace dependencies via `workspace:*` and shared upstream dependencies via the pnpm catalog (defined in `pnpm-workspace.yaml`). All packages must use identical versions of shared dependencies like `@openid4vc/oauth2`, `@openid4vc/utils`, `zod`, etc.

### Evaluating oid4vc-ts Dependencies

The SDK leverages business logic from [oid4vc-ts](https://github.com/openwallet-foundation-labs/oid4vc-ts) to avoid duplicating well-tested implementations. However, **every modification to the codebase requires evaluating whether the upstream logic still meets our requirements**.

**When to re-evaluate:**
- Before implementing new features that touch areas using oid4vc-ts logic
- When IT-Wallet specifications change or diverge from upstream behavior
- When upstream implementation constraints conflict with our needs

**Decision criteria:**

1. **Rewrite the logic locally** when:
   - Upstream behavior differs from IT-Wallet specifications
   - Future specification changes will require custom logic
   - Example: Wallet attestation creation where oid4vc-ts includes either `x5c` OR `trust_chain` in the header, but IT-Wallet specs will require both claims

2. **Upgrade oid4vc-ts version** when:
   - The new version implements the functionality we need
   - The upstream change aligns with IT-Wallet specifications
   - Check the oid4vc-ts changelog and test thoroughly before upgrading

3. **Continue using oid4vc-ts** when:
   - The logic perfectly aligns with IT-Wallet requirements
   - No specification changes are anticipated
   - The abstraction provides clear benefits without constraints

**Process:**
- When modifying code that uses oid4vc-ts methods, document which upstream functions are being used and why
- If rewriting logic, add a comment explaining why the local implementation was necessary
- Keep track of specification divergences to inform future maintenance decisions

### Code Organization Pattern

Each package follows a consistent structure:
- Top-level feature directories (e.g., `authorization-request/`, `access-token/`)
- Each feature contains:
  - Main implementation file(s)
  - `index.ts` for exports
  - Zod schemas prefixed with `z-` (e.g., `z-authorization-request.ts`)
  - `__tests__/` subdirectory with vitest tests

### Multi-Version Support Pattern

The SDK supports multiple versions of the Italian Wallet specifications simultaneously using a structured versioning pattern:

**Directory Structure:**
```
feature-name/
├── types.ts                    # Shared types and version-specific option types
├── create-feature.ts           # Version router with function overloads
├── v1.0/
│   ├── create-feature.ts       # v1.0-specific implementation
│   ├── z-schema.ts             # v1.0-specific Zod schemas
│   └── __tests__/
├── v1.3/
│   ├── create-feature.ts       # v1.3-specific implementation
│   ├── z-schema.ts             # v1.3-specific Zod schemas
│   └── __tests__/
└── __tests__/
    └── version-router.test.ts  # Tests for version routing logic
```

**Version Router Pattern:**
- Top-level function with TypeScript overloads for each version
- Switch statement routing based on `config.itWalletSpecsVersion`
- Type narrowing ensures compile-time safety
- Runtime validation for version-specific parameters

**Example:**
```typescript
// Version-specific option types
export interface FeatureOptionsV1_0 extends BaseOptions {
  config: { itWalletSpecsVersion: ItWalletSpecsVersion.V1_0 } & IoWalletSdkConfig;
}

export interface FeatureOptionsV1_3 extends BaseOptions {
  config: { itWalletSpecsVersion: ItWalletSpecsVersion.V1_3 } & IoWalletSdkConfig;
  keyAttestation: string; // Required only in v1.3
}

// Function overloads for type safety
export function createFeature(options: FeatureOptionsV1_0): Promise<FeatureV1_0>;
export function createFeature(options: FeatureOptionsV1_3): Promise<FeatureV1_3>;

// Implementation routes to version-specific logic
export async function createFeature(options: FeatureOptions): Promise<Feature> {
  switch (options.config.itWalletSpecsVersion) {
    case ItWalletSpecsVersion.V1_0:
      // Validate v1.0 constraints
      if ('keyAttestation' in options) {
        throw new ItWalletSpecsVersionError(...);
      }
      return V1_0.createFeature(options);
    case ItWalletSpecsVersion.V1_3:
      return V1_3.createFeature(options);
    default:
      throw new ItWalletSpecsVersionError(...);
  }
}
```

**Key Principles:**
- **No code duplication**: Shared logic stays in common files; only version-specific differences live in version directories
- **Type safety**: TypeScript overloads ensure consumers get correct return types based on config
- **Explicit validation**: Runtime checks prevent mixing incompatible version features
- **Exhaustiveness**: Default case in switch ensures all versions are handled
- **Clear separation**: Version-specific schemas and types live with their implementations

**When to add version support:**
- New Italian Wallet specification version is released
- Breaking changes in protocol structure (e.g., `proof` vs `proofs`)
- New required parameters for specific versions (e.g., `keyAttestation`)

**When NOT to use versioning:**
- Backward-compatible additions (add to existing implementation)
- Bug fixes (apply to all affected versions)
- Internal refactoring (maintain same external API)

When creating versioned folder structures (e.g., v1.0/, v1.3/), always update all related imports, tests, and README documentation in the same session.

## Code Quality

Always run type checks (`tsc --noEmit` or equivalent) after modifying TypeScript files, especially when changing schemas, enums, or type definitions.

## Development Commands

### Building
```bash
pnpm build              # Build all packages
pnpm types:check        # Type-check all packages
```

### Testing
```bash
pnpm test               # Run all tests (uses vitest)
pnpm test:watch         # Run tests in watch mode
vitest run <file>       # Run a specific test file
```

### Linting and Formatting
```bash
pnpm lint               # Lint and auto-fix
pnpm lint:check         # Lint without fixing
pnpm format             # Format all source files
pnpm format:check       # Check formatting without changes
```

### Pre-commit Workflows
```bash
pnpm pre-commit         # Format + lint
pnpm pre-push           # Format + lint + type-check + test
pnpm code-review        # Full check suite (type + lint + format + test)
```

### Release
```bash
pnpm release            # Build and publish to npm (uses changesets)
```

## Architecture and Conventions

### Dual-Level API Design

**Critical architectural pattern**: Each package exposes two abstraction levels for network operations:

1. **High-level functions**: Include the `fetch` call and return typed data
2. **Low-level utilities**: Request body builders and response schemas for manual HTTP handling

This allows consumers to either use built-in `fetch` or integrate with their own HTTP infrastructure.

Example from oauth2:
- High-level: `fetchTokenResponse()`
- Low-level: `createTokenRequest()` + `zTokenResponse` schema

### Error Handling

- Package-specific errors extend a base error class (e.g., `Oauth2Error` for oauth2 package)
- Granular errors per method when needed (e.g., `PushedAuthorizationRequestError`)
- All errors defined in package-level `errors.ts`
- Each method wraps operations in try/catch and throws typed errors
- Common errors from `@openid4vc/utils` (e.g., `JsonParseError`, `ValidationError`) can be reused

#### HTTP Status Check Convention

**Always use `hasStatusOrThrow` from `@pagopa/io-wallet-utils` to validate HTTP response status codes.** Never use `response.ok` or manual `if (!response.ok)` checks.

```typescript
// ✅ CORRECT
import { UnexpectedStatusCodeError, hasStatusOrThrow } from "@pagopa/io-wallet-utils";

const response = await fetch(url, init);
await hasStatusOrThrow(200, UnexpectedStatusCodeError)(response);

// ❌ WRONG
if (!response.ok) {
  throw new SomeCustomError(`Failed: ${response.status} ${response.statusText}`);
}
```

### CallbackContext Pattern

The SDK uses a **callback injection pattern** via `CallbackContext` from `@openid4vc/oauth2` to remain crypto-agnostic and environment-agnostic. This allows consumers to provide their own implementations for cryptographic operations and HTTP requests.

**Key callbacks in CallbackContext:**
- `signJwt`: Sign JWTs (e.g., for proofs, request objects)
- `generateRandom`: Generate cryptographically secure random bytes
- `hash`: Hash data (e.g., for PKCE code challenges)
- `fetch`: Make HTTP requests (for high-level functions)
- `verifyJwt`: Verify JWT signatures
- `encryptJwe`: Encrypt JWE tokens

**Usage pattern:**
Functions accept a `callbacks` parameter using TypeScript's `Pick` utility to specify only the required callbacks:

```typescript
export interface CredentialRequestOptions {
  callbacks: Pick<CallbackContext, "signJwt">;
  // ... other options
}

export interface CreatePushedAuthorizationRequestOptions {
  callbacks: Pick<CallbackContext, "generateRandom" | "hash" | "signJwt">;
  // ... other options
}
```

#### Critical Rule: Always Use Provided Callbacks

**⚠️ IMPORTANT**: When implementing SDK functions, you **MUST ALWAYS use the callbacks provided through `options.callbacks`** instead of native or global implementations. This is the core principle that makes the SDK environment-agnostic.

**✅ CORRECT - Use callbacks from options:**
```typescript
export async function fetchTokenResponse(
  options: FetchTokenResponseOptions
): Promise<TokenResponse> {
  // Use the fetch callback from options
  const { fetch } = options.callbacks;

  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: createTokenRequest(options),
  });

  return zTokenResponse.parse(await response.json());
}
```

**❌ WRONG - Using native fetch:**
```typescript
export async function fetchTokenResponse(
  options: FetchTokenResponseOptions
): Promise<TokenResponse> {
  // NEVER use native fetch directly!
  const response = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: createTokenRequest(options),
  });

  return zTokenResponse.parse(await response.json());
}
```

**✅ CORRECT - Use generateRandom callback:**
```typescript
export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptions
): Promise<AuthorizationRequest> {
  const { generateRandom } = options.callbacks;

  const state = options.state ??
    encodeToBase64Url(await generateRandom(RANDOM_BYTES_SIZE));

  // ... rest of implementation
}
```

**❌ WRONG - Using crypto.randomBytes or Math.random:**
```typescript
export async function createAuthorizationRequest(
  options: CreateAuthorizationRequestOptions
): Promise<AuthorizationRequest> {
  // NEVER use native crypto directly!
  const state = options.state ??
    encodeToBase64Url(crypto.randomBytes(RANDOM_BYTES_SIZE));

  // ... rest of implementation
}
```

#### Why This Matters

1. **Cross-platform compatibility**: Native `fetch` doesn't exist in React Native; native `crypto` modules differ between Node.js and browsers
2. **Custom implementations**: Consumers may need to add logging, retry logic, authentication, or proxying to HTTP requests
3. **Testing**: Callbacks can be easily mocked in tests without complex module mocking
4. **Security**: Consumers control cryptographic implementations (hardware security modules, specific crypto libraries)

#### Complete Example from Credential Request

**Example from [create-credential-request.ts](packages/oid4vci/src/credential-request/create-credential-request.ts):**
```typescript
export async function createCredentialRequest(
  options: CreateCredentialRequestOptions
): Promise<CredentialRequest> {
  // Extract ALL required callbacks from options
  const { signJwt } = options.callbacks;

  // Use the callback instead of any native JWT signing
  const proofJwt = await signJwt(options.signer, {
    header: {
      alg: options.signer.alg,
      jwk: options.signer.publicJwk,
      typ: "openid4vci-proof+jwt",
    },
    payload: {
      aud: options.issuerIdentifier,
      iat: dateToSeconds(new Date()),
      iss: options.clientId,
      nonce: options.nonce,
    },
  });

  return {
    format: options.format,
    proof: {
      proof_type: "jwt",
      jwt: proofJwt,
    },
  };
}
```

#### Checklist for Implementing Functions

When implementing or modifying SDK functions:

1. ✅ Identify all operations that need callbacks (fetch, crypto operations, JWT operations)
2. ✅ Add the required callbacks to the function's options type using `Pick<CallbackContext, ...>`
3. ✅ Extract callbacks from `options.callbacks` at the start of the function
4. ✅ Use the extracted callbacks throughout the function implementation
5. ✅ Never import or use native implementations (`fetch`, `crypto`, JWT libraries)
6. ✅ In tests, provide mock callbacks that verify correct usage

**High-level vs Low-level functions:**
- **High-level functions** (e.g., `fetchTokenResponse`): Must include `fetch` in their callbacks
- **Low-level functions** (e.g., `createTokenRequest`): Only include the crypto callbacks they need (e.g., `signJwt`, `generateRandom`, `hash`)

This pattern ensures the SDK works seamlessly in Node.js, browsers, and React Native by letting consumers provide platform-specific implementations.

### Cryptographic Values

Random values (`state`, `jti`, nonces, etc.) must be either:
1. Generated via the `generateRandom` callback from CallbackContext, or
2. Passed explicitly by the consumer

Never hardcode or use weak random generation. See [create-authorization-request.ts:96-100](packages/oauth2/src/authorization-request/create-authorization-request.ts) for the pattern:
```typescript
state: options.state ??
  encodeToBase64Url(
    await options.callbacks.generateRandom(RANDOM_BYTES_SIZE)
  )
```

### Public API Surface

Third-party types and utilities needed by consumers are re-exported through package `index.ts` files to maintain a clean API boundary. Example: oauth2 re-exports `SignJwtCallback`, `Jwk`, `decodeJwt`, etc. from `@openid4vc/oauth2`.

### Naming Conventions

- **Do not** prefix objects/methods with `ItWallet`
- Use descriptive, context-appropriate names
- Zod schemas: prefix with `z-` (e.g., `zAuthorizationRequest`)
- Test files: `__tests__/<feature>.test.ts`

### Code Comments

**Avoid unnecessary comments**. Write self-documenting code with clear variable and function names. Do not add comments that:

- State the obvious or describe what the code literally does
- Explain specific implementation details (e.g., "Re-throw validation errors with full context for debugging")
- Add narrative about routine operations (e.g., "Only wrap unexpected errors")

**Bad examples:**
```typescript
// Re-throw validation errors with full context for debugging
if (error instanceof ValidationError) {
  throw error;
}

// Only wrap unexpected errors
throw new Oid4vciError(
  `Unexpected error during create credential request: ${error instanceof Error ? error.message : String(error)}`,
);
```

**Good example:**
```typescript
if (error instanceof ValidationError) {
  throw error;
}

throw new Oid4vciError(
  `Unexpected error during create credential request: ${error instanceof Error ? error.message : String(error)}`,
);
```

Only add comments when:
- The logic is inherently complex and non-obvious
- There's a critical spec requirement or edge case being handled
- The "why" cannot be expressed through code structure alone

### TypeScript Configuration

- Target: ES2022
- Module: NodeNext with NodeNext resolution
- Strict mode enabled
- `noUncheckedIndexedAccess: true` for safer array/object access

## Testing Patterns

Tests use vitest with the following patterns:

- Mock external dependencies with `vi.mock()`
- Mock callbacks (e.g., `generateRandom`, `signJwt`, `hash`) as needed
- Use `describe`/`it` blocks for organization
- Type mocked functions with `vi.mocked()` for type safety

Example:
```typescript
vi.mock("@openid4vc/utils");
const mockGenerateRandom = vi.fn();
const mockCallbacks = {
  generateRandom: mockGenerateRandom,
  signJwt: vi.fn(),
};
```

## Package Manager and Node Version

- **Package Manager**: pnpm 10.14.0 (enforced via `packageManager` field)
- **Node Version**: >=20.0.0 (specified in engines, .node-version: 20.19.4)

## Compliance and Specifications

The SDK implements the Italian IT-Wallet specifications v1.0:
- https://italia.github.io/eid-wallet-it-docs/releases/1.0.2/en/

When making changes, ensure compatibility with:
- OpenID4VCI (Verifiable Credential Issuance)
- OpenID4VP (Verifiable Presentation)
- Italian Federation trust model
- OAuth 2.0 extensions: PAR, DPoP, PKCE, JARM

## Package Build Configuration

Each package uses `tsup` for building:
- Output formats: CJS + ESM + TypeScript declarations
- Source maps included
- Exports both CommonJS (`require`) and ES modules (`import`)
