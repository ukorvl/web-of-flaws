# Bash Helper Scripts Guidelines

## Scope

This directory contains Bash helper scripts that are used by GitHub Actions workflows. These scripts are intended to encapsulate logic that is too complex for a single workflow step, or that is reused across multiple workflows.

## Bash Scripts Coding Rules

- If a workflow needs to run a bash script that is not a "one-liner" command, put the script in `.github/scripts/` and call it from the workflow.
- When you put a script in `.github/scripts/`, also add a Bats test in `.github/scripts/tests/` to verify that the script runs without syntax errors and returns expected exit codes.
- When you change a script in `.github/scripts/`, also update its Bats test to cover the new behavior.
- When you create/edit tests for a script, ensure that they are essential and cover all the important scenarios. Do not add tests that only follow the script's internal implementation details. Test various inputs, outputs, and error conditions.
- Test meaningful boundary and failure cases, especially missing required inputs, empty results, malformed data, and unsafe input handling.
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
- Use `mktemp` for temporary files/directories and clean them with `trap`.
- Use `--` before path or untrusted positional arguments where supported.
- Avoid `for x in $(command)` and parsing `ls`.
- Prefer `while IFS= read -r` or arrays for command output.

## Required Checks

```bash
shellcheck .github/scripts/*.sh
bats .github/scripts/tests
```
