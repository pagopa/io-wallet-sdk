# refactor: Version Routing Dispatcher — Eliminate Manual `if/isVersion` Chains

**Jira:** WLEO-1238  
**Type:** Refactor  
**Priority:** Medium  
**Scope:** `packages/utils`, `packages/oid4vci`, `packages/oauth2`, `packages/oid4vp`, `packages/oid-federation`

---

## Overview

Approximately 12 functions across 11 files replicate the same manual version-routing pattern: a chain of `if (hasConfigVersion(...))` / `if (config.isVersion(...))` / `switch (version)` guards followed by a `throw new ItWalletSpecsVersionError(...)` default. This pattern must be manually updated in every file whenever a new `ItWalletSpecsVersion` is added, creating high maintenance cost and a significant risk of omission.

This refactor introduces a single, reusable `createVersionDispatcher` utility in `packages/utils` that encapsulates the routing logic. Each function registers its per-version handlers once; adding a new spec version only requires touching the implementation files for that version, not modifying every existing router.

---

## Problem Statement

### Current state — three variants of the same pattern across 11 files

**Pattern A — `hasConfigVersion` chain (options object carries config)**
```typescript
// packages/oid4vci/src/credential-request/create-credential-request.ts
if (isV1_0Options(options)) return V1_0.createCredentialRequest(options);
if (isV1_3Options(options)) return V1_3.createCredentialRequest(options);
throw new ItWalletSpecsVersionError("createCredentialRequest", version, [...]);
```

**Pattern B — `config.isVersion()` chain (standalone config variable)**
```typescript
// packages/oid4vci/src/credential-request/parse-credential-request.ts
if (options.config.isVersion(ItWalletSpecsVersion.V1_0)) { /* ... */ }
if (options.config.isVersion(ItWalletSpecsVersion.V1_3)) { /* ... */ }
throw new ItWalletSpecsVersionError("parseCredentialRequest", version, [...]);
```

**Pattern C — `switch` statement (bare version value)**
```typescript
// packages/oid-federation/src/metadata/itWalletMetadata.ts
switch (version) {
  case ItWalletSpecsVersion.V1_0: return parseWithErrorHandling(itWalletMetadataV1_0, ...);
  case ItWalletSpecsVersion.V1_3: return parseWithErrorHandling(itWalletMetadataV1_3, ...);
  default: throw new ItWalletSpecsVersionError(...);
}
```

### Impact of adding `ItWalletSpecsVersion.V1_5`

Today, every one of the 12 router functions must be opened and updated manually. A single missed file silently falls through to the error path at runtime, with no compile-time warning.

---

## Proposed Solution

### New utility: `createVersionDispatcher`

A factory in `packages/utils/src/version-dispatcher.ts` that:

1. Accepts a feature name string (for error messages) and a handler map keyed by `ItWalletSpecsVersion`
2. Returns a dispatcher function that reads `options.config.itWalletSpecsVersion`, calls the matching handler, and throws `ItWalletSpecsVersionError` for unregistered versions
3. Exposes `supportedVersions` so error messages are always accurate and exhaustive

```typescript
// packages/utils/src/version-dispatcher.ts

import { ItWalletSpecsVersion, ItWalletSpecsVersionError } from "./config";

type AnyOptions = { config: { itWalletSpecsVersion: ItWalletSpecsVersion } };

/**
 * Creates a version-aware dispatcher that routes a function call
 * based on options.config.itWalletSpecsVersion.
 *
 * Throws ItWalletSpecsVersionError for any unregistered version.
 *
 * @param featureName - Used in the error message when version is unsupported
 * @param handlers    - Map of version → handler function
 */
export function createVersionDispatcher<TOptions extends AnyOptions, TResult>(
  featureName: string,
  handlers: Partial<Record<ItWalletSpecsVersion, (options: TOptions) => TResult>>,
): (options: TOptions) => TResult {
  const supportedVersions = Object.keys(handlers) as ItWalletSpecsVersion[];

  return (options: TOptions): TResult => {
    const version = options.config.itWalletSpecsVersion;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const handler = (handlers as Record<string, (o: TOptions) => TResult>)[version];

    if (handler) {
      return handler(options);
    }

    throw new ItWalletSpecsVersionError(featureName, version, supportedVersions);
  };
}
```

> **Note on type safety:** Public TypeScript overloads remain unchanged (no breaking change). The `any` cast is confined to the internal dispatcher factory; consumer code sees only the existing overloads.

---

## Affected Files

The 12 routing functions mapped to their dispatcher migration:

| File | Function | Pattern | Handler delegation |
|------|----------|---------|-------------------|
| `packages/oid4vci/src/credential-request/create-credential-request.ts` | `createCredentialRequest` | A | `V1_0.createCredentialRequest`, `V1_3.createCredentialRequest` |
| `packages/oid4vci/src/credential-request/parse-credential-request.ts` | `parseCredentialRequest` | B | Extract inline v1.0/v1.3 blocks to private helpers |
| `packages/oid4vci/src/credential-request/verify-credential-request-jwt-proof.ts` | `verifyCredentialRequestJwtProof` | A | Extract inline v1.0/v1.3 blocks to private helpers |
| `packages/oid4vci/src/credential-response/create-credential-response.ts` | `buildVersionedResponse` (private) | A | `V1_0.createCredentialResponseV1_0`, `V1_3.createCredentialResponseV1_3` |
| `packages/oid4vci/src/metadata/fetch-metadata.ts` | `fetchMetadata` | B | Extract `fetchMetadataV1_0`, `fetchMetadataV1_3` private helpers |
| `packages/oid4vci/src/wallet-provider/WalletProvider.ts` | `createItWalletAttestationJwt` | A | `createWalletAttestationJwtV1_0/V1_3/V1_4` |
| `packages/oauth2/src/authorization-request/create-authorization-request.ts` | `parseAuthorizationRequestByVersion` (private) | A | Inline Zod parse calls |
| `packages/oauth2/src/authorization-request/parse-pushed-authorization-request.ts` | `getAuthorizationRequestSchema` (private) | B | Schema map `V1_0 → zAuthorizationRequestV1_0`, etc. |
| `packages/oauth2/src/client-attestation/wallet-attestation.ts` | `verifyWalletAttestationJwt` | A | `verifyWalletAttestationJwtV1_0/V1_3/V1_4` |
| `packages/oid4vp/src/authorization-request/create-authorization-request.ts` | `createAuthorizationRequest` | A | `createAuthorizationRequestWithHeader(options, headerSchemaV1_0/V1_3)` |
| `packages/oid-federation/src/metadata/itWalletMetadata.ts` | `isItWalletMetadataVersion` | C | `safeParse` handlers |
| `packages/oid-federation/src/metadata/itWalletMetadata.ts` | `parseItWalletMetadataForVersion` | C | `parseWithErrorHandling` handlers |

---

## Technical Approach

### Phase 1: Implement `createVersionDispatcher` utility

- **File:** `packages/utils/src/version-dispatcher.ts` (new file)
- **Export via:** `packages/utils/src/index.ts`
- **Unit tests:** `packages/utils/src/__tests__/version-dispatcher.test.ts`

Test cases to cover:
- Correct handler called for V1_0
- Correct handler called for V1_3
- `ItWalletSpecsVersionError` thrown for unknown version
- `supportedVersions` list in error is accurate
- Async handlers (`Promise<T>`) work correctly

### Phase 2: Migrate simple delegation cases (Pattern A, direct delegation)

Files where the handler map consists of direct function references — minimal code change, high confidence:

1. `packages/oid4vci/src/credential-request/create-credential-request.ts`
2. `packages/oid4vci/src/credential-response/create-credential-response.ts` (`buildVersionedResponse`)
3. `packages/oauth2/src/client-attestation/wallet-attestation.ts`
4. `packages/oid4vp/src/authorization-request/create-authorization-request.ts`

**Example — before:**
```typescript
// packages/oid4vci/src/credential-request/create-credential-request.ts
export async function createCredentialRequest(
  options: CredentialRequestOptions,
): Promise<CredentialRequest> {
  const { config } = options;

  if (isV1_0Options(options)) {
    return V1_0.createCredentialRequest(options);
  }
  if (isV1_3Options(options)) {
    return V1_3.createCredentialRequest(options);
  }
  throw new ItWalletSpecsVersionError(
    "createCredentialRequest",
    (config as { itWalletSpecsVersion: string }).itWalletSpecsVersion,
    [ItWalletSpecsVersion.V1_0, ItWalletSpecsVersion.V1_3],
  );
}
```

**After:**
```typescript
// packages/oid4vci/src/credential-request/create-credential-request.ts
const dispatchCreateCredentialRequest = createVersionDispatcher<
  CredentialRequestOptions,
  Promise<CredentialRequest>
>("createCredentialRequest", {
  [ItWalletSpecsVersion.V1_0]: V1_0.createCredentialRequest,
  [ItWalletSpecsVersion.V1_3]: V1_3.createCredentialRequest,
});

export async function createCredentialRequest(
  options: CredentialRequestOptions,
): Promise<CredentialRequest> {
  return dispatchCreateCredentialRequest(options);
}
```

The `isV1_0Options` / `isV1_3Options` local type guards can be deleted.

### Phase 3: Migrate schema/config-returning cases (Pattern B helpers)

Files where the handler returns a schema or config object rather than delegating a complex function:

5. `packages/oauth2/src/authorization-request/parse-pushed-authorization-request.ts` (`getAuthorizationRequestSchema`)
6. `packages/oid4vci/src/wallet-provider/WalletProvider.ts` (class method refactor)

For `WalletProvider.ts`, the class method `createItWalletAttestationJwt` references `this.specVersion` instead of `options.config`. A wrapper options object can be created, or the dispatcher can be pre-bound in the constructor:

```typescript
// packages/oid4vci/src/wallet-provider/WalletProvider.ts
const dispatchCreateWalletAttestation = createVersionDispatcher<
  { config: IoWalletSdkConfig } & WalletAttestationOptions,
  Promise<string>
>("createItWalletAttestationJwt", {
  [ItWalletSpecsVersion.V1_0]: (o) => {
    assertV1_0Options(o);
    return createWalletAttestationJwtV1_0({ ... });
  },
  // ...
});
```

### Phase 4: Migrate complex inline logic cases

Files with non-trivial code inside each version branch. These require extracting the branch code into private named helpers before the dispatcher can be used:

7. `packages/oid4vci/src/credential-request/parse-credential-request.ts`
8. `packages/oid4vci/src/credential-request/verify-credential-request-jwt-proof.ts`
9. `packages/oid4vci/src/metadata/fetch-metadata.ts`
10. `packages/oauth2/src/authorization-request/create-authorization-request.ts` (`parseAuthorizationRequestByVersion`)

**Extraction strategy for `verify-credential-request-jwt-proof.ts`:**

```typescript
// Before — inline blocks inside verifyCredentialRequestJwtProof
if (hasConfigVersion(options, ItWalletSpecsVersion.V1_0)) {
  // 30 lines of inline logic
}
if (hasConfigVersion(options, ItWalletSpecsVersion.V1_3)) {
  // 40 lines of inline logic
}

// After — extract to private functions, then dispatch
async function verifyProofV1_0(
  options: VerifyCredentialRequestJwtProofOptionsV1_0,
): Promise<VerifyCredentialRequestJwtProofResultV1_0> {
  // same 30 lines
}

async function verifyProofV1_3(
  options: VerifyCredentialRequestJwtProofOptionsV1_3,
): Promise<VerifyCredentialRequestJwtProofResultV1_3> {
  // same 40 lines
}

const dispatchVerifyProof = createVersionDispatcher<
  VerifyCredentialRequestJwtProofOptions,
  Promise<VerifyCredentialRequestJwtProofResult>
>("verifyCredentialRequestJwtProof", {
  [ItWalletSpecsVersion.V1_0]: verifyProofV1_0,
  [ItWalletSpecsVersion.V1_3]: verifyProofV1_3,
});
```

### Phase 5: Migrate switch-statement cases (Pattern C)

11. `packages/oid-federation/src/metadata/itWalletMetadata.ts` (`isItWalletMetadataVersion`, `parseItWalletMetadataForVersion`)

These functions take a bare `version: ItWalletSpecsVersion` value with no `options` object. A lightweight second utility or an overload of `createVersionDispatcher` can handle this:

```typescript
// packages/utils/src/version-dispatcher.ts (addendum)

/**
 * Dispatches by a bare version value (no options object needed).
 */
export function dispatchByVersion<TResult>(
  featureName: string,
  version: ItWalletSpecsVersion,
  handlers: Partial<Record<ItWalletSpecsVersion, () => TResult>>,
): TResult {
  const handler = handlers[version];
  if (handler) return handler();
  throw new ItWalletSpecsVersionError(
    featureName,
    version,
    Object.keys(handlers) as ItWalletSpecsVersion[],
  );
}
```

Applied to `parseItWalletMetadataForVersion`:
```typescript
// packages/oid-federation/src/metadata/itWalletMetadata.ts
export function parseItWalletMetadataForVersion<V extends ItWalletSpecsVersion>(
  metadata: unknown,
  version: V,
): ItWalletMetadataByVersion<V> {
  return dispatchByVersion("parseItWalletMetadataForVersion", version, {
    [ItWalletSpecsVersion.V1_0]: () =>
      parseWithErrorHandling(itWalletMetadataV1_0, metadata, "invalid v1.0 metadata provided"),
    [ItWalletSpecsVersion.V1_3]: () =>
      parseWithErrorHandling(itWalletMetadataV1_3, metadata, "invalid v1.3 metadata provided"),
  }) as ItWalletMetadataByVersion<V>;
}
```

---

## Acceptance Criteria

- [ ] `createVersionDispatcher` exists in `packages/utils/src/version-dispatcher.ts` and is exported from `packages/utils/src/index.ts`
- [ ] `dispatchByVersion` exists in the same file (for bare-version routing without an options object)
- [ ] All 12 routing functions use one of the two new dispatcher utilities
- [ ] Adding a new `ItWalletSpecsVersion` enum value requires changes only in version-specific implementation files, not in existing routers
- [ ] All public TypeScript overloads remain unchanged (zero breaking change for SDK consumers)
- [ ] All local `isV1_X`, `assertV1_X`, `isV1_XOptions` type guard functions that existed solely for routing are deleted
- [ ] `pnpm types:check` passes on all packages
- [ ] `pnpm test` passes on all packages with no test modifications
- [ ] New unit tests for `createVersionDispatcher` and `dispatchByVersion` achieve full branch coverage

---

## Dependencies & Risks

| Risk | Mitigation |
|------|-----------|
| TypeScript inference with `any` inside dispatcher | Cast is internal-only; public overloads remain typed. Reviewed with `tsc --strict`. |
| `WalletProvider` uses `this.specVersion` instead of `options.config` | Wrap in a synthetic options object `{ config: this.config }` or pre-bind dispatcher in constructor |
| Some branches have complex side effects (error-catching try/catch wrapping the dispatch) | Keep outer try/catch in place; dispatcher replaces only the version-routing switch, not the error handling layer |
| 4 packages touched simultaneously | Migrate one package at a time; run `pnpm test` after each package migration |
| `fetch-metadata.ts` has branching beyond simple dispatch (`federationResult ?? fallback`) | Extract per-version helpers that include the full branch logic; dispatcher delegates to helpers |

---

## Implementation Order

```
Phase 1  →  packages/utils (new utility + tests)
Phase 2  →  packages/oid4vci (simple delegation cases)
           packages/oauth2 (simple delegation cases)
           packages/oid4vp (simple delegation)
Phase 3  →  packages/oid4vci (WalletProvider class)
           packages/oauth2 (parse-pushed-authorization-request)
Phase 4  →  packages/oid4vci (parse-credential-request, verify-credential-request-jwt-proof, fetch-metadata)
           packages/oauth2 (create-authorization-request inline helper)
Phase 5  →  packages/oid-federation (itWalletMetadata switch cases)
```

Run `pnpm types:check && pnpm test` after each phase before proceeding.

---

## Internal References

- Current version enum and type guard: `packages/utils/src/config.ts:4`
- `ItWalletSpecsVersionError`: `packages/utils/src/errors/errors.ts:70`
- Representative router (Pattern A): `packages/oid4vci/src/credential-request/create-credential-request.ts:75`
- Representative router (Pattern B): `packages/oauth2/src/authorization-request/parse-pushed-authorization-request.ts:125`
- Representative router (Pattern C): `packages/oid-federation/src/metadata/itWalletMetadata.ts:106`
- Most complex inline logic: `packages/oid4vci/src/credential-request/verify-credential-request-jwt-proof.ts:205`
- Three-version router example: `packages/oid4vci/src/wallet-provider/WalletProvider.ts:274`
- `packages/utils/src/index.ts:1` — where the new export must be added
