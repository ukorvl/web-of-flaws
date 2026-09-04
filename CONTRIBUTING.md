# Contributing to Web of Flaws

Web of Flaws is a catalog of vulnerable web patterns and their safer replacements. Contributions
should be technically accurate, concise, and useful both to developers and security-review tools.

This guide is for human contributors. The repository's detailed automation contract lives in
[`AGENTS.md`](AGENTS.md) and its directory-specific instruction files.

## Getting Started

You need Python 3.12, `markdownlint-cli2`, Ruff, and Git. Install `uv` for mutation testing and
Bats when working on workflow shell scripts.

Before opening a pull request, run:

```bash
markdownlint-cli2
ruff check scripts
ruff format --check scripts
python3 scripts/check.py
python3 -m unittest discover -s scripts/tests -v
```

Use `markdownlint-cli2 --fix` for safe Markdown formatting fixes. Run `prek install` to enable the
repository's staged-file and commit-message hooks.

## Adding a Guide

1. Check that the pattern is not already covered, then choose the narrowest existing category.
2. Add one Markdown rule file with a permanent `WOF-<FAMILY>-<NUMBER>` ID and YAML frontmatter.
3. Choose `vulnerability`, `weakness`, or `hardening-gap` honestly; do not call every missing
   defense an exploitable vulnerability.
4. Use `dataflow` with explicit `sources` and `sinks`, or `semantic-pattern` with `indicators`.
   These models are mutually exclusive.
5. Explain the trust boundary, the conditions that make the pattern exploitable, safer alternatives,
   and meaningful false positives.
6. Cite authoritative references. External guide URLs must be allowlisted in
   `catalog/allowed-reference-domains.json`.
7. Update the nearest category `README.md`.

Rule headings and frontmatter are validated automatically. Read
[`guides/AGENTS.md`](guides/AGENTS.md) for the complete guide contract before editing a guide.

## Generated Data

Guides are the source of truth. Do not edit `catalog/rules.json`, `.github/labeler.yaml`, or
`.github/labels.yaml` by hand.

After changing guide metadata, run:

```bash
python3 scripts/generate_catalog.py
```

After changing guide groups, run:

```bash
python3 scripts/sync_guide_labels.py
```

`python3 scripts/check.py` verifies that generated data, references, standards mappings, and labels
remain consistent.

## Tooling and Workflows

Add tests for changes to repository Python tooling. For mutations, use the locked environment:

```bash
uv run --locked --only-group mutation mutmut run
uv run --locked --only-group mutation mutmut results
```

Workflow changes must keep Actions SHA-pinned and pass `yamllint .github`, `zizmor .github`, and
`actionlint -color`. Shell workflow scripts also require `bats .github/scripts/tests`.

## Pull Requests

Keep each pull request focused. Explain the security pattern or infrastructure change, the validation
you ran, and any known detection limits or false positives. Target the `main` branch.
