# GitHub Automation Instructions

## Scope

This directory contains GitHub Actions workflows, workflow-local shell scripts and tests,
repository labels, Dependabot policy, and Copilot integration instructions.

## Coding Rules

### Pin Every External Dependency To An Exact Version Whenever Possible

- For third-party GitHub Actions, pin to a full commit SHA.
- Retain the human-readable release as a comment: `uses: owner/action@<sha> # vX.Y.Z`.
- Pin language-specific dependencies to exact versions.
- Pin runtime versions such as Node.js, Python, Go, etc. Never use `latest` when specifying `runs-on` or `setup-<language>` actions.
- Pin system-level packages and external CLI tools when possible.
- Do not use mutable versions such as latest, main, master, next, or floating ranges.
- If a dependency cannot be pinned, report it explicitly and add a TODO comment explaining why.

### Principle Of Least Privilege

- Use the minimum required permissions for each workflow and action.
- Prefer contents: read or no explicit write permissions for validation jobs.
- Do not grant repository-wide write permissions for convenience.
- Keep privileged operations isolated from validation and test logic.
- Prefer contents: read or no explicit write permissions for validation jobs.
- Never use `write-all`.

### Secrets

- Never print secrets.
- Never pass secrets through command-line arguments when avoidable.
- Never write secrets to outputs, logs, caches, or artifacts.
- Avoid writing secrets to files. If a tool requires it, use a temporary permission-restricted file and remove it immediately after use.
- Secrets must be accessed only by authorized workflows/jobs and the steps that require them.
- For greater control, prefer environment-specific secrets, which can be protected by manual approvals or specific branch conditions.
- Never cache secrets or store them in a way that they can be retrieved by unauthorized workflows or jobs.

### Timeouts And Network Access

- Avoid unnecessary network access in workflows and don't rely on network access for validation unless it is the explicit purpose of the workflow. Always use timeouts for network operations to avoid hangs.
- If you rely on external data, verify its integrity and authenticity. Don't assume its shape and always check for missing or unexpected fields.
- Add timeout-minutes to jobs that can hang or access external systems.
- Keep retry counts small and explicit.
- Retry transient external failures, not deterministic validation failures.

### Cache And Artifact Rules

- Treat caches only as performance optimizations; correctness must not depend on cache presence.
- Include relevant lockfile/configuration hashes in dependency cache keys.
- Treat artifacts downloaded from untrusted workflow runs as untrusted input.
- Upload only artifacts that are intentionally needed.
- Do not upload credentials, environment dumps, or sensitive runner state.

### Checkout Rules

- Use `actions/checkout` only when repository contents are required.
- Use `persist-credentials: false` unless later authenticated Git operations are explicitly required.
- Fetch only the history required by the workflow.
- Set `fetch-depth` explicitly when Git history or diff computation depends on it.
- Never check out attacker-controlled refs in a privileged workflow context.

### Other General Rules

- Don't modify global runner state unless necessary.
- Put complex shell/Python logic in `.github/scripts/`; keep YAML declarative.
- Don't depend on commands that are not guaranteed to exist without installing them.
- Avoid obscure third-party actions when a few shell lines or an official action suffice.
- Prefer GitHub-authored or well-established actions and minimize the number of third-party actions. Review what every third-party action can access if you use it.
- Do not use deprecated ::set-output command.
- Do not manually overwrite `GITHUB_*` / `RUNNER_*` variables.
- Treat artifacts and metadata originating from untrusted workflows as untrusted.
- Never execute untrusted PR-controlled code or artifacts inside a privileged `workflow_run` or `pull_request_target` context.

### Workflow Structure Guidelines

- Workflows should be clear, modular, and easy to understand, promoting reusability and maintainability.
- Always start with a descriptive name and appropriate `on` triggers. Suggest granular triggers for specific use cases (e.g., on: push: branches: [main] vs. on: pull_request).
- Define jobs with clear name and appropriate `runs-on` (e.g., ubuntu-24.04).
- Add `concurrency` when duplicate or stale runs can conflict, waste resources, or produce outdated results.
- Prefer `cancel-in-progress: true` for replaceable PR validation.
- Do not cancel releases, publishing, deployments, migrations, or other stateful operations unless cancellation is explicitly safe.
- All steps should have descriptive names.
- Always try to make code self-explanatory and avoid unnecessary comments. If a comment is needed, explain the "why" rather than the "what."

## Required Checks

```bash
yamllint .github
zizmor .github
actionlint
shellcheck .github/scripts/*.sh
```

If label generation changes, run `python3 scripts/check.py --check labels`.
