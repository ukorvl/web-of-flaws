---
id: WOF-SUPPLY-002
title: "Mutable Third-Party CI Action Executes Trusted Workflow"
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-829
  owasp_top_10:
    - "A03:2025 Software Supply Chain Failures"
platforms:
  - ci-cd
languages:
  - yaml
detection:
  type: semantic-pattern
  methods:
    - grep
    - ast
    - semantic-review
  candidate_tokens:
    - "uses:"
    - "@main"
    - "@master"
    - "@v"
    - "permissions:"
indicators:
  - workflow steps that use third-party actions by branch or mutable tag instead of a full commit SHA
  - release, deploy, publish, signing, or artifact jobs that execute mutable external actions with secrets or write permissions
  - workflows that rely on broad `GITHUB_TOKEN` or cloud credentials while importing actions from repositories outside the organization
  - pull requests that change `uses:` targets, action owners, or action version refs without pinning to an immutable commit
tags:
  - supply-chain
  - github-actions
  - ci-cd
  - mutable-ref
  - secrets
---

## Rule

Treat third-party GitHub Actions as untrusted code until pinned to an immutable revision.
Do not run third-party actions from mutable refs such as branches or movable tags in trusted workflows; pin them to a full commit SHA before they can access secrets, write tokens, releases, or deployment paths.

## Mental Model

```text
third-party action ref
      ↓
branch or movable tag changes
      ↓
trusted CI workflow execution
      ↓
workflow secrets or write permissions
      ↓
release compromise or secret theft
```

The workflow file is not just configuration.
When a job executes an external action, it is importing and running third-party code with the privileges of that runner and workflow context.

## Why This Matters

Trusted CI jobs often hold deployment credentials, package publishing tokens, signing keys, artifact upload rights, or repository write access.
If a workflow references `some-org/action@main` or a mutable tag such as `@v1`, the action code can change after review without the workflow file changing again.
That turns action compromise, tag retargeting, or maintainer account takeover into immediate workflow code execution.

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
    permissions:
      contents: write
      packages: write
    steps:
      - uses: actions/checkout@v5

      - name: Build release
        run: npm ci && npm run build

      - name: Publish package
        uses: some-org/publish-action@main
        with:
          registry-token: ${{ secrets.NPM_TOKEN }}
```

## Example Attack

```text
1. A trusted workflow references some-org/publish-action@main.
2. The action repository is compromised, or the mutable ref is retargeted.
3. The next release run fetches the new action code automatically.
4. The malicious action reads credentials exposed to that step or job and modifies the release output.
```

## Why The Attack Works

1. The workflow trusts an external action by owner and mutable ref rather than an immutable commit.
2. A branch such as `main` or a movable tag such as `v1` can point to different code later.
3. GitHub Actions resolves that ref at workflow runtime and executes the referenced action code.
4. The action receives the runner environment, the job's token scope, and any secrets or inputs explicitly exposed to that action step or the whole job.
5. A compromised action can exfiltrate credentials, publish malicious artifacts, or rewrite release outputs without another workflow diff.

## Safer Pattern

Pin third-party actions to a full commit SHA, reduce workflow permissions, and review ref changes as code execution changes.

```yaml
name: release

on:
  push:
    tags:
      - "v*"

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332

      - name: Build release
        run: npm ci && npm run build

      - name: Publish package
        uses: some-org/publish-action@8f4b7f84864484a7bf31766abe9204da3cbe65b3
        with:
          registry-token: ${{ secrets.NPM_TOKEN }}
```

If a team intentionally keeps a GitHub-authored action such as `actions/checkout` on a major tag for maintenance convenience, treat that as an explicit risk decision and document it as a warning rather than silently treating it as safe.

## Detection

Detection type: `semantic-pattern`.

- Candidate collection: inspect workflow YAML for `uses:` steps that reference external actions by branch names such as `main` or `master`, or by tags such as `v1`, `v2`, or `latest`, instead of a full commit SHA.
- Candidate collection: diff `.github/workflows/*.yml` changes for action owner changes, repo changes, or ref changes, especially in release, deploy, publish, signing, or artifact workflows.
- Confirmation: verify that the referenced action is third-party or otherwise mutable and that the workflow gives that action step a privileged effect such as explicit secret access, write-scoped `GITHUB_TOKEN`, cloud credentials, artifact publishing, deployment execution, or release modification.
- High-confidence signals include mutable third-party actions in jobs with `contents: write`, `packages: write`, OIDC cloud login, signing steps, production deploys, or publish credentials.
- GitHub-authored actions such as `actions/*` or `github/*` may be treated by some teams as lower-risk warnings when pinned only to major tags, but GitHub still documents full-length commit SHA pinning as the immutable option and repository or organization policy can require SHAs even for GitHub-authored actions.
- A scanner should surface mutable action refs and privileged workflow contexts; the agent or reviewer should confirm whether the ref is third-party, whether the workflow is trusted, and whether policy or risk acceptance allows a non-SHA exception.

## False Positives

- A third-party action pinned to a full commit SHA is usually not this rule, even if the repository also publishes mutable tags.
- Local actions such as `uses: ./.github/actions/build` are not third-party imports, though they still deserve ordinary code review.
- A mutable ref in a low-privilege, secret-free workflow may be lower priority, but it is still a trust-boundary warning if the action comes from outside the repository.
- Some organizations intentionally allow GitHub-authored actions by tag under a documented exception policy; treat that as a warning or policy exception rather than an automatically safe pattern.

## Framework Notes

This guide focuses on GitHub Actions because the `uses:` syntax makes mutable refs especially easy to review and lint.
The same trust boundary appears in other CI systems whenever a pipeline imports externally maintained build logic by branch or tag rather than an immutable revision.

## References

- [MITRE CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Top 10 2025 A03: Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [GitHub Docs: Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Docs: Managing GitHub Actions settings for a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
- [GitHub Docs: Using immutable releases and tags to manage your action's releases](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/using-immutable-releases-and-tags-to-manage-your-actions-releases)
- [GitHub Docs: Immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases)

## Quick Checklist

- Third-party GitHub Actions are pinned to full commit SHAs in trusted workflows.
- Action ref changes are reviewed with the same care as code execution changes.
- Release, deploy, signing, and publish jobs minimize `GITHUB_TOKEN` permissions and secret exposure.
- Mutable refs in GitHub-authored actions are documented as explicit warnings or policy exceptions, not silently assumed safe.
- Repository or organization policy requires full-length commit SHA pinning when possible.
