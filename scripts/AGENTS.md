# Repository Tooling Instructions

## Scope

This directory contains deterministic Python tooling for catalog generation, guide linting, standards
validation, label synchronization, and the central `check.py` entry point. `tests/` contains its
unit tests and fixtures.

## Design Rules

- Keep repository orchestration in `check.py`; CI should invoke it rather than duplicate repository
  logic in shell steps.
- Preserve direct execution with `python3 scripts/<script>.py`. Modules that also need package
  imports must support both execution modes.
- Report validation failures clearly to stderr and return a nonzero status. Do not silently skip an
  invalid file, a failed subprocess, or a missing invariant.
- Add or update focused unit tests for every behavior change. Use temporary fixture repositories;
  tests must not mutate the real repository.
- Regenerate derived files with their scripts rather than constructing their output in tests or CI.

## Required Checks

```bash
ruff check scripts
ruff format --check scripts
python3 -m unittest discover -s scripts/tests -v
python3 scripts/check.py
```

For mutation-related changes, also run:

```bash
uv run --locked --only-group mutation mutmut run
uv run --locked --only-group mutation mutmut results
```
