# Repository Guidelines

## Project Structure & Module Organization

This is a pnpm TypeScript monorepo for the IO Wallet SDK. Public packages live under `packages/*`, with source code in each package's `src/` directory and package entry points in `src/index.ts`. Tests are colocated in `__tests__/` folders, for example `packages/oid4vci/src/credential-offer/__tests__/`. Version-specific protocol code uses directories such as `v1.0/` and `v1.3/`; keep version routers at the feature level and shared types in nearby `types.ts` files. Package builds emit `dist/`, which should not be edited manually.

## Build, Test, and Development Commands

Use `pnpm install` with Node `>=22.22.2` (`.node-version` is authoritative). Key commands:

- `pnpm build`: builds all workspace packages with their package-local `build` scripts.
- `pnpm test`: runs the Vitest suite once.
- `pnpm test:watch`: runs Vitest in watch mode while developing.
- `pnpm types:check`: builds packages, then runs `tsc --noEmit`.
- `pnpm lint:check` / `pnpm lint`: checks or fixes ESLint issues.
- `pnpm format:check` / `pnpm format`: checks or applies Prettier formatting.
- `pnpm code-review`: runs type checks, lint checks, formatting checks, and tests.

## Coding Style & Naming Conventions

Write TypeScript using ES modules and explicit public exports from each package entry point. Formatting is handled by Prettier; linting uses `@pagopa/eslint-config` through `eslint.config.mjs`, including `@typescript-eslint/consistent-type-exports`. Follow existing file naming: implementation files use kebab case (`create-credential-request.ts`), Zod schemas are prefixed with `z-`, and tests end in `.test.ts`. Do not add the `ItWallet` prefix to object or method names.

## Testing Guidelines

Vitest is the test framework. Add tests next to the code they cover in `__tests__/`, and name them after the behavior or module under test, such as `parse-credential-offer-uri.test.ts`. Cover version-specific behavior separately when adding or changing `v1.0/`, `v1.3/`, or newer protocol branches. Run `pnpm test` before submitting and `pnpm code-review` for full validation.

## Commit & Pull Request Guidelines

The history follows Conventional Commit style: `feat(scope): ...`, `fix(scope): ...`, `docs: ...`, `refactor: ...`, and `chore(release): ...`. Keep commits focused and include a Changeset when package behavior or public APIs change. Pull requests should describe the change, link related issues, list validation commands run, and call out affected packages or protocol versions. Request review from the listed code owners when changes touch owned areas.

## Security & Configuration Tips

Keep dependency versions aligned through `pnpm-workspace.yaml` catalogs. Do not hardcode cryptographic randomness; use the shared `generateRandom` callback or accept caller-provided values. Avoid committing credentials, generated `dist/` output, or local environment files.
