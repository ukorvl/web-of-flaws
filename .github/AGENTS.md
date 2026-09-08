# GitHub Automation Instructions

## Scope

This directory contains GitHub Actions workflows, workflow-local shell scripts and tests,
repository labels, Dependabot policy, and Copilot integration instructions.

## Coding Rules

### General Guidelines

#### Pin Every External Dependency To An Exact Version Whenever Possible

- For third-party GitHub Actions, pin to a full commit SHA.
- Retain the human-readable release as a comment: uses: `owner/action@<sha> # vX.Y.Z`.
- Pin language-specific dependencies to exact versions.
- Pin runtime versions such as Node.js, Python, Go, Java, etc.
- Pin system-level packages and external CLI tools when possible.
- Do not use mutable versions such as latest, main, master, next, or floating ranges.
- If a dependency cannot be pinned, report it explicitly and add a TODO comment explaining why.

#### Use Principle Of Least Privilege

- Use the minimum required permissions for each workflow and action.
- Prefer contents: read or no explicit write permissions for validation jobs.
- Do not grant repository-wide write permissions for convenience.
- Keep privileged operations isolated from validation and test logic.

#### Working With Secrets Rules

- Never print secrets.
- Never pass secrets through command-line arguments when avoidable.
- Never write secrets to outputs, logs, artifacts, or files.
- Secrets must be accessed only by authorized workflows/jobs and the steps that require them.
- For greater control, prefer environment-specific secrets, which can be protected by manual approvals or specific branch conditions.

#### Other General Rules

- Don't modify global runner state unless necessary.
- Put complex shell/Python logic in `.github/scripts/`; keep YAML declarative.
- Don't depend on commands that are not guaranteed to exist without installing them.
- Avoid obscure third-party actions when a few shell lines or an official action suffice.
- Prefer GitHub-authored or well-established actions and minimize the number of third-party actions. Review what every third-party action can access if you use it.
- Do not use deprecated ::set-output.
- Do not manually overwrite `GITHUB_*` / `RUNNER_*` variables.
- Errors should identify the file/item that failed.
- Avoid unnecessary network access in workflows and don't rely on network access for validation unless it is the explicit purpose of the workflow. Always use timeouts for network operations to avoid hangs.
- If you rely on external data, verify its integrity and authenticity. Don't assume its shape and always check for missing or unexpected fields.
- Always add a proper concurrency block to workflows to avoid race conditions and accidental double runs.
- Avoid using pull_request_target when building or running code submitted from forks; reserve it strictly for safe, non-code metadata workflows

### Workflow Strcucture Guidelines

### Composite Action Guidelines

- When you encounter a repeated workflow pattern, consider creating a composite action in `.github/actions/` to encapsulate it and keep the code DRY.
- Extract an action when logic is reused or conceptually independent, not merely because YAML is long.
- Composite actions must be fully self-contained and not depend on any external workflows.
- Follow the principle: one composite action = one clear responsibility.
- Prefer names like `.github/actions/python-scripts-check/action.yml`.
- Always provide name and concise description.
- Keep inputs minimal and don't add inputs that are not vitally necessary.
- Use kebab-case input/output names.
- Treat all action inputs as untrusted strings.
- Avoid hidden behavior controlled by undocumented environment variables.
- Define outputs only when callers actually need them.
- Give steps meaningful names.
- Always specify shell: bash for run: steps.
- Never eval input.
- Never execute input as a command.
- Permissions belong in the workflow, not the composite action.
- Never make a validation action mutate the repository.
- Produce concise diagnostic output which is readable for humans and parsable by machines.

### Bash Helper Script Guidelines

- If a workflow needs to run a bash script that is not a "one-liner" command, put the script in `.github/scripts/` and call it from the workflow.
- When you put a script in `.github/scripts/`, also add a Bats test in `.github/scripts/tests/` to verify that the script runs without syntax errors and returns expected exit codes.
- When you change a script in `.github/scripts/`, also update its Bats test to cover the new behavior.
- When you create/edit tests for a script, ensure that they are essential and cover all the important scenarios. Do not add tests that only follow the script's internal implementation details. Test various inputs, outputs, and error conditions.
- Always test corner cases and unexpected inputs, including empty inputs, missing required environment variables, and malformed data.
- Use `set -euo pipefail` at the top of every bash script to ensure that errors are not ignored and that the script exits on failure.
- One script = one responsibility.
- Use descriptive kebab-case filenames.
- Bash scripts must start with #!/usr/bin/env bash.
- Quote all variable expansions unless intentional splitting is required.
- Prefer [[ ... ]] over [ ... ] in Bash.
- Use "${array[@]}" when passing array arguments.
- Never execute arbitrary input as shell code.
- Treat environment variables, filenames, branch names, PR metadata, and GitHub context as untrusted input.
- Scripts should not install their own runtimes unless installation is their explicit responsibility.
- Never silently ignore command failures. If failure is intentionally ignored, document why.
- Keep output concise but easily understandable by humans.
- Prefer resolving repository root explicitly instead of assuming $PWD.
- Use functions for meaningful logical units.
- Keep main/top-level execution easy to read.
- Prefer early exits over deeply nested conditionals.
- Avoid dynamic imports from repository-controlled paths.
- Keep scripts independently runnable locally where practical.
- Required variables must fail immediately when missing.
- Script behavior must not differ between local and CI without explicit reason.
- Keep scripts small; split them when responsibilities diverge.
- A script must never broaden workflow permissions.
- Prefer read-only behavior by default.
- Every script should be deterministic, testable, fail-safe, and locally reproducible.
- Never interpolate untrusted ${{ ... }} directly into shell code.
- Never build shell commands by string concatenation.

## Required Checks

```bash
yamllint .github
zizmor .github
actionlint
shellcheck .github/scripts/*.sh
```

For changes under `.github/scripts/`, also run:

```bash
bash -n .github/scripts/run-mutation-tests.sh
prek run shellcheck --all-files
bats .github/scripts/tests
```

If label generation changes, run `python3 scripts/check.py --check labels`.
