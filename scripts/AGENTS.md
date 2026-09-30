# TypeScript Repository Tooling Instructions

## Scope

This directory owns guide parsing, repository validation, deterministic catalog and label generation,
workflow helpers, and their tests. These scripts protect compatibility-sensitive security metadata.

## TypeScript and Runtime

- Use strict TypeScript and ESM; follow `tsconfig.base.json` and `tsconfig.json`.
- Scripts run directly with Node.js type stripping. Use explicit `.ts` import extensions,
  `import type` for types, and erasable syntax. Do not introduce a transpiler or a build step for scripts.
- Use `unknown` at JSON/YAML and external-process boundaries and narrow it before use. Avoid `any`.
- Keep parsing, validation, transformation, filesystem I/O, subprocesses, and CLI handling separate.
- Prefer pure functions and explicit parameters over mutable module state. Export testable entry points.
- Resolve repository paths from the script location, independent of the caller's working directory.
- Use UTF-8 and deterministic sorting. Generate complete output before replacing destination files.
- Check modes must never repair data. Report actionable errors on stderr and return nonzero on failure.
- Never silently swallow parsing, filesystem, or subprocess failures.

## Data and Process Boundaries

- Use real structured-data parsers. Reject duplicate keys, unsupported fields, malformed shapes,
  duplicate identifiers, and ambiguous security metadata; centralize the shared guide schema.
- Keep the frontmatter YAML subset explicit. Reject aliases, anchors, custom tags, flow collections,
  block scalars, unsafe object keys, and excessive nesting. Preserve string-valued metadata.
- Do not weaken the catalog schema or reference/domain checks to accommodate migration issues.
- Invoke child processes with argument arrays and an explicit working directory, never dynamic shell code.
- Use NUL-delimited Git output for paths. Include deleted and renamed source paths when selecting checks.
- If selective validation is uncertain, run the full relevant suite. Missing Git metadata is not a skip signal.
- Dependency or shared-runtime changes must invalidate all affected checks.

## Dependencies and Tests

- Add exact versions through pnpm; update `package.json` and `pnpm-lock.yaml` together.
- Validation never updates locks or installs missing tools. Do not add download fallbacks.
- Cover changed behavior in `scripts/tests/*.test.ts`; put reusable fixtures in `scripts/tests/support.ts`.
- Test observable success, failure, malformed-input and boundary behavior with temporary filesystem fixtures.
- Tests must not modify the real repository or require network access, credentials, or execution order.
- Preserve behavioral assertions when porting tests. Verify deterministic generated output.
- Workflow helper logic uses TypeScript and Vitest here, rather than a separate shell test stack.

## Required Checks

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm check
```

For mutation-tested logic, also run `pnpm test:mutation`. For a focused iteration, pass
`--mutate scripts/<module>.ts`; run the full suite before completing a broad tooling change.
Use `pnpm test:coverage` to verify coverage reporting.
