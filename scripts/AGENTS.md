# Python Repository Tooling Instructions

## Scope

This directory contains Python tooling for repository validation, catalog generation,
guide parsing, standards validation, label synchronization, and related maintenance tasks.

These scripts are part of the repository's integrity layer. Changes here may affect guides,
generated catalog data, CI validation, and downstream machine-readable consumers.

## Python Rules

- Prefer the Python standard library unless an external dependency provides substantial value.
- Add type annotations to function parameters and return values.
- Prefer precise types over `Any`.
- Use `pathlib.Path` for filesystem paths.
- Read and write text files using explicit UTF-8 encoding.
- Prefer immutable data structures for configuration and value objects when practical.
- Keep module-level mutable state to a minimum.
- Keep parsing, validation, transformation, filesystem I/O, subprocess execution, and CLI handling
  separated when practical.
- Prefer pure functions for repository-domain logic so behavior can be tested without filesystem
  or process side effects.
- Keep functions focused on one responsibility.
- Prefer explicit control flow over clever or overly compact implementations.
- Catch only exceptions that can be handled meaningfully.
- Do not silently swallow parsing, validation, filesystem, or subprocess errors.

## Filesystem and Generated Data

- Resolve the repository root from the script location when behavior depends on repository-relative paths.
- Do not rely on the caller's current working directory unless that is an explicit interface requirement.
- Sort filesystem-derived collections when order affects generated output or diagnostics.
- Do not rely on filesystem traversal order.
- Generated output must be deterministic.
- Prefer generating complete output in memory before replacing an existing generated file.
- Use temporary files or directories for intermediate state when needed.
- Avoid modifying unrelated repository files as a side effect of validation.

## Structured Data and Validation

- Use proper parsers for structured formats.
- Do not parse JSON, YAML, or similar structured data with regular expressions or shell pipelines.
- Validate required fields and expected value shapes explicitly.
- Reject unsupported or unexpected fields when the repository format is intentionally strict.
- Detect duplicate identifiers and conflicting entries.
- Do not silently normalize malformed security metadata when rejection is safer.
- Centralize shared guide/catalog validation rules instead of duplicating them across scripts.
- Treat guide schema and catalog structure as compatibility-sensitive contracts.

## Subprocess Rules

- Use `subprocess.run()` with an argument list.
- Never use `shell=True` with dynamic or repository-controlled input.
- Do not construct shell commands by concatenating strings.
- Set `cwd` explicitly when command behavior depends on repository location.
- Use `check=True` when failure should abort immediately.
- Use `check=False` only when the return code is intentionally handled.
- Capture subprocess output only when it is consumed.
- Preserve useful failure context in diagnostics.

## Fail-safe Validation

- When selective or incremental validation cannot reliably determine what must run, fall back to the
  broader validation.
- Never interpret missing Git metadata, malformed input, or detection uncertainty as permission to skip a check.
- Prefer running extra validation over silently missing an affected repository invariant.
- Validation scripts should detect invalid state, not automatically repair it unless repair is the explicit
  purpose of the script.

## Dependencies

- Keep runtime dependencies minimal.
- Pin every added Python dependency to an exact version.
- Update `pyproject.toml` and `uv.lock` together when dependency state changes.
- Use locked dependency execution where the repository already provides it.
- Do not update dependency locks implicitly during validation.

## Tests

- Behavioral changes in `scripts/` must be covered by tests in `scripts/tests/`.
- Bug fixes should include a regression test when practical.
- Test observable behavior and repository invariants, not internal implementation details.
- Prefer real temporary filesystem fixtures over mocking `Path`.
- Tests must not modify the real repository.
- Tests must not depend on network access, developer credentials, or execution order.
- Cover meaningful success, failure, malformed-input, and boundary cases.
- Keep shared fixture-building helpers in `scripts/tests/support.py` when they are genuinely reusable.
- Do not weaken assertions merely to accommodate changed implementation behavior.

## Required Checks

For changes under `scripts/`, run:

```bash
ruff check scripts
ruff format --check scripts
python3 -m unittest discover -s scripts/tests -v
python3 scripts/check.py
```

If mutation-tested logic changes, also run the relevant mutation test command defined by the repository.
