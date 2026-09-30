# Contributing to Web of Flaws

Web of Flaws is a catalog of vulnerable web patterns and their safer replacements. Contributions
should be technically accurate and useful both to developers and security-review tools.

## Getting Started

Install the exact Node.js version in `.node-version` (currently 24.21.0), pnpm 12.6.0, and Git.
The private root package contains repository development tools; it is never published.

```bash
npm install --global pnpm@12.6.0
pnpm install --frozen-lockfile
pnpm validate
```

The npm command only bootstraps pnpm. Use pnpm for all repository dependencies and commands.
An existing Corepack installation can also select the version declared by `packageManager`.
`pnpm validate` runs formatting/lint checks, type checking, tests, and repository integrity checks.
`pnpm check` runs just catalog, guide, standards, and generated-label validation.

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm check
pnpm check --check guides
pnpm check --changed-only
```

Changed-only mode is for local working-tree changes (staged, unstaged, and untracked files),
not a PR diff. A clean tree, missing Git metadata, or no matching changes runs the selected checks.
CI always runs the full integrity checks.

Use `pnpm format` for TypeScript/JSON formatting and `pnpm exec markdownlint-cli2 --fix` for Markdown.
Enable hooks explicitly with `pnpm hooks:install`; installation does not automatically modify Git hooks.
When migrating an existing checkout, this replaces the old pre-commit and commit-msg hooks.
The pre-commit hook validates the working tree without rewriting or staging files; commit-msg uses
conventional commits. Review existing custom hooks before replacing them.
If your Git configuration sets `core.hooksPath`, reconcile that setting with your hook manager first.

## Workspace Layout and Dependencies

`pnpm-workspace.yaml` is the workspace source of truth, with one root lockfile and a `packages/*`
pattern reserved for future packages. Current tooling stays in `scripts/`; no empty packages are needed.

- Add actual TypeScript packages under `packages/<name>` with their own `package.json` and tsconfig
  extending `../../tsconfig.base.json`. Declare each package's runtime dependencies in that package.
- Reference local packages using `workspace:*` (or `workspace:^` for a versioned publishable dependency).
  Automatic linking by matching registry versions is disabled, so missing local packages fail explicitly.
- Use `pnpm --filter <package-name> <command>` for a package, and `pnpm -r <command>` for package tasks.
  Root `pnpm validate` currently validates repository tooling; when adding packages, wire their lint,
  typecheck, test, and build scripts into root validation and CI explicitly.
- Use `pnpm add -Dw <tool>@<version>` for root tools and `pnpm --filter <name> add <dependency>@<version>`
  for package dependencies. Exact versions are saved; commit manifest and lockfile updates together.
- Keep pnpm's isolated dependency layout and strict peer dependency checks. Do not enable broad hoisting
  to hide undeclared dependencies. Introduce a pnpm dependency catalog when multiple packages actually
  share versions, and separate it clearly from the security-rule data under `catalog/`.
- Dependency releases must be at least seven days old. Unreviewed lifecycle builds fail installation;
  review the package and make an explicit `allowBuilds` decision before adding an exception.
  Dependency installation does not install Git hooks. Validation refuses stale dependencies instead
  of silently downloading or rewriting locks. CI uses `pnpm install --frozen-lockfile`.
- Add future Rust code as a Cargo workspace under `crates/`, with its own lockfile and checks. A pnpm
  package may later wrap the CLI, but Rust does not need a placeholder npm package today.

See the [pnpm workspace documentation](https://pnpm.io/workspaces) and
[build policy settings](https://pnpm.io/settings/build) for the underlying configuration.

## Adding a Guide

1. Check that the pattern is not already covered, then choose the narrowest existing category.
2. Add one Markdown rule file with a permanent `WOF-<FAMILY>-<NUMBER>` ID and YAML frontmatter.
3. Choose `vulnerability`, `weakness`, or `hardening-gap` honestly; do not call every missing
   defense an exploitable vulnerability.
4. Use `dataflow` with explicit `sources` and `sinks`, or `semantic-pattern` with `indicators`.
   These models are mutually exclusive.
5. Explain the trust boundary, exploitation conditions, safer alternatives, and meaningful false positives.
6. Cite authoritative references. External guide URLs must be allowlisted in
   `catalog/allowed-reference-domains.json`.
7. Update the nearest category `README.md`.

Frontmatter uses block mappings and lists with string scalars. Quote values containing YAML syntax.
Aliases, anchors, custom tags, flow collections, block scalars, duplicate keys, and unsafe object keys
are rejected. Quoted escape sequences follow YAML semantics.

## Generated Data

Guides are the source of truth. Do not edit `catalog/rules.json`, `.github/labeler.yaml`, or
`.github/labels.yaml` by hand.

```bash
pnpm generate:catalog
pnpm generate:labels
pnpm check
```

Both generators accept `--check` to detect stale or missing output without writing files.
The catalog schema remains version 1; generation must remain deterministic.

## Tests and Workflows

Add Vitest tests for repository tooling changes. Tests use temporary repositories and need no network.
Node.js executes scripts using native type stripping; `pnpm typecheck` checks their types separately.

```bash
pnpm test:coverage
pnpm test:mutation
pnpm test:mutation --mutate scripts/guide-tools.ts
```

Coverage produces `coverage/lcov.info` for Coveralls. Stryker produces HTML and JSON under
`reports/mutation/` plus a console report. Mutation scores are informational (break threshold 0),
matching the previous reporting policy; test failures and mutation-runner errors still fail the job.
PR mutation runs may target changed production modules; test/config changes, deletions, or uncertainty
run the full suite. Scheduled and manual runs always cover all production scripts.

Workflow changes must keep Actions SHA-pinned and pass `pnpm lint:config`, `zizmor .github`, and
`actionlint -color`. The last two are standalone native tools; CI pins their actions and versions.
There is no separate workflow shell helper or shell-test runtime to install.

## Pull Requests

Keep each pull request focused. Explain the change, the validation you ran, and any known detection
limits or false positives. Target the `main` branch.
