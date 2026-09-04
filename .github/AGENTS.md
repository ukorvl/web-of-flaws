# GitHub Automation Instructions

## Scope

This directory contains GitHub Actions workflows, workflow-local shell scripts and tests,
repository labels, Dependabot policy, and Copilot integration instructions.

## Coding Rules

### General Guidelines

- Pin every external dependency to an exact version whenever possible.
  - For third-party GitHub Actions, pin to a full commit SHA.
  - Retain the human-readable release as a comment: uses: `owner/action@<sha> # vX.Y.Z`.
  - Pin language-specific dependencies to exact versions.
  - Pin runtime versions such as Node.js, Python, Go, Java, etc.
  - Pin system-level packages and external CLI tools when possible.
  - Do not use mutable versions such as latest, main, master, next, or floating ranges.
  - If a dependency cannot be pinned, report it explicitly and add a TODO comment explaining why.

### Composite Action Guidelines

- When you encounter a repeated workflow pattern, consider creating a composite action in `.github/actions/` to encapsulate it and keep the code DRY.
- Extract an action when logic is reused or conceptually independent—not merely because YAML is long.
- Composite actions must be fully self-contained and not depend on any external scripts or workflows.
- Follow the principle: one composite action = one clear responsibility.
- Prefer names like `.github/actions/python-scripts-check/action.yml`.
- Always provide name and concise description.
- Keep inputs minimal.
- Use kebab-case input/output names.
- Treat all action inputs as untrusted strings.
- Avoid hidden behavior controlled by undocumented environment variables.
- Define outputs only when callers actually need them.
- Give steps meaningful names.
- Always specify shell: bash for run: steps.
- Never interpolate untrusted ${{ ... }} directly into shell code.
- Never eval input.
- Never execute input as a command.
- Never build shell commands by string concatenation.
- Prefer argument arrays/scripts over generated shell.
- Put complex shell/Python logic in `.github/scripts/`; keep YAML declarative.
- Never depend on the caller's current directory accidentally.
- Don't modify global runner state unless necessary.
- Don't depend on commands that are not guaranteed to exist without installing them.
- Avoid obscure third-party actions when a few shell lines or an official action suffice.
- Prefer GitHub-authored or well-established actions.
- Minimize the number of third-party actions.
- Review what every third-party action can access.
- Never print secrets.
- Never pass secrets through command-line arguments when avoidable.
- Never write secrets to normal outputs.
- Do not use deprecated ::set-output.
- Do not manually overwrite `GITHUB_*` / `RUNNER_*` variables.
- Permissions belong in the workflow, not the composite action.
- Workflows should explicitly declare minimal permissions:. GitHub recommends least-privilege permissions.
- Never make a validation action mutate the repository.
- Avoid depending on mutable external data.
- Don't hide failures with || true.
- Don't use continue-on-error for required checks.
- Use fail-on-error: false only when failure is intentionally non-blocking and documented.
- Don't swallow exit codes.
- Produce concise diagnostic output which is readable for humans and parsable by machines.
- Errors should identify the file/item that failed.
- Keep conditions simple.
- Parenthesize complicated expressions rather than relying on precedence.
- Don't use secrets in if: expressions.
- Keep action interfaces stable.

### Bash Script Guidelines

- If a workflow needs to run a bash script that is not a "one-liner" command, put the script in `.github/scripts/` and call it from the workflow.
- When you put a script in `.github/scripts/`, also add a Bats test in `.github/scripts/tests/` to verify that the script runs without syntax errors and returns expected exit codes.
- When you change a script in `.github/scripts/`, also update its Bats test to cover the new behavior.
- When you create/edit tests for a script, ensure that they are essential and cover all the important scenarios. Do not add tests that only follow the script's internal implementation details. Test various inputs, outputs, and error conditions.
- Always test corner cases and unexpected inputs, including empty inputs, missing required environment variables, and malformed data.
- Use `set -euo pipefail` at the top of every bash script to ensure that errors are not ignored and that the script exits on failure.
- Prefer scripts over large run: | YAML blocks.
- One script = one responsibility.
- Use descriptive kebab-case filenames.
- Bash scripts must start with #!/usr/bin/env bash.
- Quote all variable expansions unless intentional splitting is required.
- Prefer [[ ... ]] over [ ... ] in Bash.
- Use "${array[@]}" when passing array arguments.
- Never use eval.
- Never execute arbitrary input as shell code.
- Never construct commands by concatenating untrusted strings.
- Treat environment variables, filenames, branch names, PR metadata, and GitHub context as untrusted input.
- Avoid parsing ls.
- Use readarray / mapfile when appropriate.
- Never print secrets or tokens.
- Do not pass secrets via CLI arguments when avoidable.
- Do not write secrets to artifacts or logs.
- Scripts should not install their own runtimes unless installation is their explicit responsibility.
- Prefer project-managed dependencies and lockfiles.
- Avoid network access unless required.
- Make network-dependent behavior explicit.
- Add timeouts to network operations.
- Never silently ignore command failures.
- If failure is intentionally ignored, document why.
- Preserve meaningful exit codes.
- Exit 0 only for successful/expected outcomes.
- Keep output concise but easily understandable by humans.
- Prefer deterministic output.
- Prefer correctness over CI optimization.
- Prefer resolving repository root explicitly instead of assuming $PWD.
- Do not rely accidentally on the workflow's working directory.
- Use functions for meaningful logical units.
- Keep main/top-level execution easy to read.
- Prefer early exits over deeply nested conditionals.
- Keep I/O separate from transformation/validation logic.
- Avoid dynamic imports from repository-controlled paths.
- Keep scripts independently runnable locally where practical.
- Required variables must fail immediately when missing.
- Do not silently invent important defaults.
- Script behavior must not differ between local and CI without explicit reason.
- Tests must not mutate the developer's repository.
- Keep scripts small; split them when responsibilities diverge.
- A script must never broaden workflow permissions.
- Scripts should not assume `GITHUB_TOKEN` exists.
- Scripts should not call GitHub APIs unless that is their explicit responsibility.
- Prefer read-only behavior by default.
- Every script should be deterministic, testable, fail-safe, and locally reproducible.

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
