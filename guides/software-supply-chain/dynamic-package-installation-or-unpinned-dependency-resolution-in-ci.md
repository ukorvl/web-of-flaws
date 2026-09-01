---
id: WOF-SUPPLY-006
title: "Mutable Dependency Resolution in Trusted CI"
kind: hardening-gap
default_severity: medium
exploitability: medium
standards:
  cwe:
    - CWE-829
  owasp_top_10:
    - id: "A03:2025 Software Supply Chain Failures"
      relationship: related
platforms:
  - ci-cd
languages:
  - json
  - shell
  - yaml
detection:
  type: semantic-pattern
  methods:
    - grep
    - ast
    - semantic-review
  candidate_tokens:
    - npm install
    - npm exec
    - npx
    - "@latest"
    - package-lock.json
indicators:
  - CI steps that run `npm install <pkg>@latest`, `npm i <pkg>@latest`, `npx <pkg>`, or `npm exec` against packages that are not available in the repository's reviewed lockfile
  - workflows that remove, regenerate, or rewrite `package-lock.json`, or that use `npm install` without consuming a reviewed in-sync lockfile
  - release, build, signing, publish, or artifact-generation jobs whose outputs depend on live npm registry resolution at workflow runtime
  - pull requests that remove lockfile enforcement or replace `npm ci` with mutable install flows in trusted automation
tags:
  - supply-chain
  - npm
  - npx
  - ci-cd
  - dependency-pinning
  - mutable-resolution
---

## Rule

Treat runtime package resolution in trusted CI as third-party code execution from mutable external state.
Do not let build, release, signing, or publish jobs dynamically fetch tools via `npx`, `npm exec`, or `npm install ...@latest`, and do not let CI rebuild dependency trees from live registry state.
A version range in `package.json` is not this issue when CI consumes a committed, in-sync lockfile with `npm ci`.

## Mental Model

```text
CI workflow step
      ↓
live registry lookup or lockfile regeneration
      ↓
mutable package version
      ↓
trusted runner privileges
      ↓
code execution, artifact drift, or secret theft
```

The repository commit is no longer the full build input.
Once CI resolves packages from mutable registry state, the same source revision can execute different code on different runs.

## Why This Matters

Trusted CI often has publish tokens, signing material, deployment credentials, or permission to generate release artifacts.
If a workflow runs `npm install some-tool@latest`, `npx some-tool`, or regenerates its lockfile in CI, the resulting build can change without any new repository diff.
That turns an upstream package compromise, malicious new release, or simply an unexpected dependency update into immediate CI code execution or artifact tampering.

## Vulnerable Pattern

```yaml
name: release

on:
  push:
    tags:
      - "v*"

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332

      - name: Rebuild the dependency lockfile in CI
        run: rm -f package-lock.json && npm install

      - name: Install release helper dynamically
        run: npm install --no-save changelog-publisher@latest

      - name: Publish release notes
        run: npx changelog-publisher publish
```

```json
{
  "private": true,
  "devDependencies": {
    "vite": "^5.4.8",
    "changelog-publisher": "^2.3.0"
  }
}
```

## Example Attack

```text
1. A trusted workflow runs npm install, npm install <tool>@latest, or npx <tool>.
2. An attacker publishes or compromises a new version that still matches the mutable spec.
3. The next CI run resolves the new package version from the registry.
4. The package or its install-time behavior executes on the trusted runner.
5. The attacker steals CI credentials or alters the generated release artifacts.
```

## Why The Attack Works

1. The workflow allows runtime dependency resolution from npm instead of consuming the reviewed dependency tree from source control.
2. `npm install <pkg>@latest` and rebuilding a lockfile allow newer published versions to be selected later.
3. `npx` and `npm exec` can fetch packages that are not already present locally, then execute their binaries in the CI job.
4. The resolved package and its install-time behavior run with the runner's filesystem, network, environment, and workflow credentials.
5. The build result depends on mutable external registry state rather than only on the reviewed repository revision.

## Safer Pattern

Commit `package-lock.json`, use `npm ci` in CI, and perform dependency refreshes only in reviewed changesets that commit the resulting lockfile updates together.
The lockfile, not an exact version spec in `package.json`, is what freezes the dependency tree used by CI.

```diff
{
  "private": true,
  "scripts": {
+   "release:notes": "changelog-publisher publish"
  },
  "devDependencies": {
    "vite": "^5.4.8",
    "changelog-publisher": "^2.3.0"
  }
}
```

```yaml
name: release

on:
  push:
    tags:
      - "v*"

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332

      - name: Install the reviewed dependency tree
        run: npm ci

      - name: Publish release notes with the reviewed local tool
        run: npm run release:notes
```

If a tool must be upgraded, do it in a dedicated dependency update or release-engineering PR, review the exact version change, and commit the updated `package-lock.json` before CI consumes it.

## Detection

Detection type: `semantic-pattern`.

- Candidate collection: inspect workflow YAML and shell scripts for `npm install <pkg>@latest`, `npm i <pkg>@latest`, `npx <pkg>`, `npm exec`, `npm update`, or other live package resolution inside trusted CI jobs.
- Candidate collection: inspect `package.json` and workflow diffs for dist-tags such as `latest`, unpinned git refs, or package-manager commands that can resolve packages outside the committed lockfile.
- Candidate collection: inspect workflow steps that remove, regenerate, or rewrite `package-lock.json`, or that replace `npm ci` with `npm install` in artifact-producing jobs.
- Confirmation: verify that the workflow resolves package versions from npm at runtime, or rebuilds the dependency tree from live registry state, and that the resolved package can execute code or materially influence a trusted build, release, signing, deployment, or artifact output.
- Confirmation requires both dynamic resolution and a reachable privileged effect. A lone `^` or `~` in `package.json` is not enough if CI only uses a committed in-sync `package-lock.json` via `npm ci`.
- High-confidence signals include release, publish, deploy, signing, or artifact-generation jobs that use mutable installs, unversioned `npx`, or lockfile regeneration in CI.
- Treat `devDependencies` as in scope when they are installed or executed in CI, because tooling dependencies can still compromise the trusted pipeline.

## False Positives

- `npm ci` with a committed `package-lock.json` that is already in sync is usually not this rule, even if `package.json` contains ranges, because CI is consuming a frozen dependency tree rather than resolving new versions.
- `npx` or `npm exec` that only invokes a local tool from the repository's reviewed dependency tree is lower risk than remote resolution from the registry.
- A dependency update PR that changes version ranges but commits the resulting lockfile for review is not this rule when CI consumes that lockfile with `npm ci`.
- One-off local developer experimentation outside trusted CI is out of scope for this rule.

## Framework Notes

This guide focuses on npm semantics because `npm install`, `npx`, `npm exec`, `package.json`, and `package-lock.json` make the trust boundary easy to describe.
The same underlying issue appears in any package manager when trusted automation resolves packages from live registry state or rebuilds lockfiles during the workflow itself.

## References

- [MITRE CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Top 10 2025 A03: Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [npm Docs: npm install](https://docs.npmjs.com/cli/install/)
- [npm Docs: npm exec](https://docs.npmjs.com/cli/npm-exec/)
- [npm Docs: npm ci](https://docs.npmjs.com/cli/commands/npm-ci/)
- [npm Docs: package.json](https://docs.npmjs.com/files/package.json/)
- [npm Docs: package-lock.json](https://docs.npmjs.com/files/package-lock.json/)

## Quick Checklist

- Trusted CI jobs do not run `npm install <pkg>@latest` or unversioned remote `npx` for build or release tooling.
- Dependencies executed in CI are resolved from a reviewed lockfile.
- `package-lock.json` is committed, reviewed, and consumed with `npm ci`.
- Lockfile regeneration and dependency refreshes happen in explicit reviewed PRs, not during release or publish workflows.
- Dynamic package resolution in CI is treated as third-party code execution, not as harmless build plumbing.
