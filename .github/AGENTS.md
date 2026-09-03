# GitHub Automation Instructions

## Scope

This directory contains GitHub Actions workflows, workflow-local shell scripts and Bats tests,
repository labels, Dependabot policy, and Copilot integration instructions.

## Workflow Rules

- Workflows orchestrate repository logic; put reusable shell behavior in `.github/scripts/` and
  cover it with Bats tests in `.github/scripts/tests/`.
- Pin every third-party action to a full commit SHA and retain a version comment. Use least-privilege
  permissions and set `persist-credentials: false` on checkout unless a workflow requires otherwise.
- Start every CI job with the existing Harden Runner audit step. Keep its human-facing comment.
- Shell scripts must use `set -euo pipefail` and return failures to the workflow. Do not hide command
  failures in pipelines, subshells, or unconditional success handlers.
- `.github/labeler.yaml` and `.github/labels.yaml` are generated. Change guide groups, then run
  `python3 scripts/sync_guide_labels.py`; do not edit either generated file manually.

## Required Checks

```bash
yamllint .github
zizmor .github
actionlint -color
```

For changes under `.github/scripts/`, also run:

```bash
bash -n .github/scripts/run-mutation-tests.sh
bats .github/scripts/tests
```

If label generation changes, run `python3 scripts/check.py --check labels`.
