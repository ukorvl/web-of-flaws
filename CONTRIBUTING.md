# Contributing to Web of Flaws

- [Contributing to Web of Flaws](#contributing-to-web-of-flaws)
  - [Getting Started](#getting-started)
  - [Repository Structure](#repository-structure)
  - [Adding a New Guide](#adding-a-new-guide)
  - [Notes Versus Rules](#notes-versus-rules)
  - [Rule IDs](#rule-ids)
  - [Frontmatter](#frontmatter)
  - [Rule Kinds](#rule-kinds)
    - [`vulnerability`](#vulnerability)
    - [`weakness`](#weakness)
    - [`hardening-gap`](#hardening-gap)
  - [Default Severity and Exploitability](#default-severity-and-exploitability)
  - [Detection Models](#detection-models)
    - [Dataflow](#dataflow)
    - [Semantic Pattern](#semantic-pattern)
  - [Required Guide Structure](#required-guide-structure)
  - [Writing the Rule](#writing-the-rule)
  - [Mental Model](#mental-model)
  - [Vulnerable Pattern](#vulnerable-pattern)
  - [Example Attack](#example-attack)
  - [Why The Attack Works](#why-the-attack-works)
  - [Safer Pattern](#safer-pattern)
  - [Detection](#detection)
  - [False Positives](#false-positives)
  - [Framework Notes](#framework-notes)
  - [References](#references)
  - [Updating Category Indexes](#updating-category-indexes)
  - [Generated Files](#generated-files)
  - [Validation](#validation)
  - [Pull Requests](#pull-requests)
  - [Changes to the Rule Format](#changes-to-the-rule-format)
  - [Contribution Philosophy](#contribution-philosophy)

Thanks for contributing to Web of Flaws.

Web of Flaws is a structured knowledge base of web security flaws, vulnerable patterns, attack paths, and safer replacements. It is designed to be useful both to humans learning web security and to coding agents reviewing real-world code.

Contributions should therefore optimize for three things:

- technical correctness;
- clear explanation;
- predictable machine-readable structure.

## Getting Started

This is a documentation-first repository. There is no application build step.

You should have:

- Python 3;
- `markdownlint-cli2`;
- `ruff`;
- `prek`;
- Git.

Before submitting changes, run:

```bash
markdownlint-cli2 "**/*.md"
ruff check scripts
ruff format --check scripts
python3 scripts/lint_repo.py
python3 scripts/generate_catalog.py --check
python3 scripts/validate_standards.py
python3 -m unittest discover -s scripts/tests -v
```

If guide categories were added, removed, or renamed, also run:

```bash
python3 scripts/sync_guide_labels.py --check
```

`prek` hooks are also available for staged-file checks and commit message linting.
Commit messages should follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), for example `docs: clarify catalog generation`.

```bash
prek install
```

## Repository Structure

Security guides live under `guides/` and are grouped by vulnerability family.

For example:

```text
guides/
├── cross-origin-communication/
├── injection/
│   └── xss/
├── request-authenticity/
└── sensitive-data-exposure/
```

Each category contains a `README.md` that acts as an index.

Each individual rule is one Markdown file with YAML frontmatter.
Category directories may contain `README.md` index files, but rules themselves are not split across multiple files.

`catalog/rules.json` is generated from these guide files and must not be edited manually.

## Adding a New Guide

Before creating a new rule:

1. Check that an equivalent rule does not already exist.
2. Prefer a specific, reusable security pattern over a broad security topic.
3. Make sure the issue represents a real vulnerability, weakness, or defense-in-depth gap supported by reputable references.
4. Choose the narrowest existing category that fits the rule.
5. Add the guide to the nearest category `README.md`.

Use exactly one Markdown file per rule.

## Notes Versus Rules

Some security topics are real and worth documenting, but still make poor catalog rules.
Common examples include social-engineering-driven attacks, analyst context, and educational edge cases that do not map cleanly to a concrete application pattern a scanner or coding agent can confirm.

When that happens:

1. Keep the catalog schema strict for actual rules.
2. Add a separate Markdown note under the nearest category's `notes/` directory and link it from the parent category `README.md`.
3. Do not assign notes a `WOF-*` ID or require rule frontmatter, standards, default severity, exploitability, or detection metadata.
4. Keep notes out of `catalog/rules.json`; they are for context, education, and reviewer guidance rather than scanner-facing rule selection.
5. Promote the topic to a full rule only when you can phrase a real application-side `vulnerability`, `weakness`, or `hardening-gap` with confirmable detection logic.

Notes should still be maintained as first-class documentation.
Use a separate file so related topics can scale cleanly as the repository grows, but do not loosen the structured rule schema to make informational content fit the catalog.

Notes should mirror normal rule structure as closely as possible even though they are not rule files.
The main differences are:

- no YAML frontmatter;
- no `WOF-*` identifier;
- `## Summary` replaces `## Rule`.

Every note should follow this exact outline:

```md
# Note Title

## Summary

## Mental Model

## Why This Matters

## Vulnerable Pattern

## Example Attack

## Why The Attack Works

## Safer Pattern

## Detection

## False Positives

## References

## Quick Checklist
```

The goal is to keep notes explicit, comparable, and easy for both humans and agents to scan, while still keeping them outside the machine-readable rule catalog.

## Rule IDs

Every rule must have a stable ID:

```text
WOF-<FAMILY>-<NUMBER>
```

Examples:

```text
WOF-XSS-001
WOF-CSRF-001
WOF-PM-001
```

IDs are permanent identifiers.

Do not reuse an existing ID for a different vulnerability, even if a guide is renamed or moved.

## Frontmatter

Every guide must begin with YAML frontmatter.

Example dataflow rule:

```yaml
---
id: WOF-CSRF-001
title: "Attacker-controlled Input to Authenticated Request Sink (Client-side CSRF)"
kind: vulnerability
default_severity: high
exploitability: medium

standards:
  cwe:
    - CWE-352
  owasp_top_10:
    - "A01:2025 Broken Access Control"

platforms:
  - browser

languages:
  - html
  - javascript
  - typescript

detection:
  type: dataflow
  methods:
    - grep
    - ast
    - taint-analysis
    - semantic-review
  candidate_tokens:
    - fetch(
    - XMLHttpRequest
    - location.search

sources:
  - window.location.search
  - MessageEvent.data

sinks:
  - fetch()
  - XMLHttpRequest.send()

tags:
  - csrf
  - client-side-csrf
---
```

Keep metadata concise and machine-readable.

Do not introduce new frontmatter fields without discussing whether they belong in the common rule schema.

Quote YAML values containing parser-sensitive characters such as `:`, `#`, or leading special characters.

For example:

```yaml
- "javascript:"
```

## Rule Kinds

Use `kind` to distinguish the nature of the finding.
Valid values are `vulnerability`, `weakness`, and `hardening-gap`.

### `vulnerability`

Use when the pattern can directly create an exploitable security issue when its required conditions are met.

Examples:

- attacker-controlled data reaching an HTML execution sink;
- attacker-controlled request instructions reaching an authenticated request sink.

### `weakness`

Use for security-relevant patterns that increase risk but are not necessarily exploitable on their own.

### `hardening-gap`

Use when the finding is a meaningful defense-in-depth gap, but the absence of the control should not automatically be reported as an exploitable vulnerability.

Do not classify every missing security control as a vulnerability.

## Default Severity and Exploitability

`default_severity` describes the default or typical impact of a **confirmed instance** of the rule.

`exploitability` describes the default or typical ease of exploitation for a **confirmed instance** of the rule.

These are rule-level defaults, not per-finding scanner verdicts.

## Detection Models

Rules currently use two main detection models.
These models are mutually exclusive.

### Dataflow

Use `dataflow` when security depends on attacker-controlled information reaching a sensitive sink.

Declare explicit `sources` and `sinks`.
Do not declare `indicators` on `dataflow` rules.

Example:

```text
URLSearchParams
      ↓
attacker-controlled string
      ↓
innerHTML
      ↓
DOM XSS
```

Typical detection methods include:

```yaml
methods:
  - grep
  - ast
  - taint-analysis
  - semantic-review
```

Optional `candidate_tokens` may be added under `detection` to give scanners and coding agents cheap lexical hints for candidate discovery.
These hints should narrow the search space, not prove exploitation on their own.

A scanner should identify candidate flows.

A human or coding agent should confirm whether the flow is actually exploitable.

### Semantic Pattern

Use `semantic-pattern` when the weakness depends primarily on the presence and surrounding meaning of a code pattern rather than a source-to-sink flow.

Declare `indicators` instead of inventing artificial sources and sinks.
Do not declare `sources` or `sinks` on `semantic-pattern` rules.

The rule must explain what additional context is necessary to confirm the finding.

When a rule has obvious low-cost lexical signals, add optional `detection.candidate_tokens` entries such as API names, sink names, protocol markers, or event names.

## Required Guide Structure

Guides must use the following sections:

```text
## Rule
## Mental Model
## Why This Matters
## Vulnerable Pattern
## Example Attack
## Why The Attack Works
## Safer Pattern
## Detection
## False Positives
[optional sections]
## References
## Quick Checklist
```

Keep the order consistent.

Optional sections such as `Framework Notes` or `Scope Notes` may appear before `References`.

## Writing the Rule

`Rule` should state the security invariant as directly as possible.

Prefer:

> Do not let attacker-controlled browser input determine the URL, method, headers, or body of an authenticated state-changing request.

Avoid vague advice such as:

> Be careful when making requests.

The rule should remain useful across frameworks and applications.

## Mental Model

Explain the underlying security mechanism.

Prefer models such as:

```text
untrusted source
      ↓
transformation
      ↓
security-sensitive sink
      ↓
impact
```

or:

```text
untrusted principal
      ↓
trust boundary
      ↓
privileged operation
```

This section should teach the reader why the vulnerability exists, not merely restate the rule.

## Vulnerable Pattern

Provide a minimal, realistic example.

Code should:

- be self-contained enough to understand;
- use modern APIs and language syntax;
- clearly expose the dangerous behavior;
- avoid unrelated complexity.

Comments should highlight the security-relevant lines.

Do not deliberately make examples unrealistic just to make the vulnerability obvious.

## Example Attack

Show how attacker control reaches the vulnerable behavior.

Examples should be concrete but concise.

Use reserved/example domains for illustrative URLs where possible.

## Why The Attack Works

Describe the actual exploitation path step by step.

This section should identify the important trust assumptions and security boundaries.

Do not claim an impact that is not demonstrated by the vulnerable pattern.

## Safer Pattern

Show a realistic secure replacement.

The safe example should address the root cause rather than hiding the dangerous operation behind superficial validation.

Prefer allowlists, explicit mappings, safe APIs, schema validation, or removal of attacker influence where appropriate.

## Detection

Detection guidance should help tools find **candidates**, not pretend that simple pattern matching proves exploitation.

Describe:

- candidate sources or indicators;
- candidate sinks;
- relevant guards;
- conditions required to confirm the finding;
- high-confidence signals;
- when semantic review is necessary.

For example:

```text
scanner
   ↓
candidate
   ↓
context / dataflow review
   ↓
confirmed finding or false positive
```

Do not equate the mere presence of a dangerous API with a vulnerability.

## False Positives

Every guide must explain realistic cases where a scanner might find the pattern but the code is safe.

Examples include:

- attacker input is not actually reachable;
- a strict allowlist removes attacker control;
- trusted sanitization exists before the sink;
- origin validation happens in a wrapper;
- the operation is read-only rather than privileged.

False-positive guidance is especially important because this repository is intended for automated security review.

## Framework Notes

Framework-specific information is optional.

Use it when a framework changes how the general vulnerability appears in practice.

Keep the underlying rule framework-independent whenever possible.

For example, React's `dangerouslySetInnerHTML`, Vue's `v-html`, and raw DOM `innerHTML` can all be manifestations of the same underlying HTML injection rule.

## References

Every guide must contain authoritative references supporting the vulnerability and recommended mitigation.

Every `standards.cwe` and `standards.owasp_top_10` entry must also have a matching canonical reference URL under `## References`.

Prefer primary or well-established security sources such as:

- MITRE CWE;
- OWASP;
- MDN;
- official framework documentation;
- official standards or specifications.

External links under `guides/` must use domains listed in:

```text
catalog/allowed-reference-domains.json
```

If a necessary domain is not present:

1. verify that the source is authoritative;
2. add the domain to the allowlist with a clear scope and rationale;
3. verify the exact URL manually.

Prefer canonical destination URLs rather than redirecting links.

Do not invent references or cite sources that do not support the claim being made.

## Updating Category Indexes

When adding a new guide, update the nearest category `README.md`.

When adding a new category, update the appropriate parent index or the repository `README.md`.

Keep names and descriptions short and consistent with related rules.
Category indexes must use inline Markdown links such as `[Rule](rule.md)`, not reference-style links such as `[Rule][rule]`.

## Generated Files

The Markdown guides under `guides/` are the source of truth.

Do not manually edit:

```text
catalog/rules.json
```

After changing guide metadata, regenerate it with:

```bash
python3 scripts/generate_catalog.py
```

Then verify that the committed output is current:

```bash
python3 scripts/generate_catalog.py --check
```

If guide categories change, regenerate GitHub labels:

```bash
python3 scripts/sync_guide_labels.py
```

## Validation

Before opening a pull request, run:

```bash
markdownlint-cli2 "**/*.md"
ruff check scripts
ruff format --check scripts
python3 scripts/lint_repo.py
python3 scripts/generate_catalog.py --check
python3 scripts/sync_guide_labels.py --check
python3 scripts/validate_standards.py
python3 -m unittest discover -s scripts/tests -v
```

If Markdown formatting needs automatic fixes:

```bash
markdownlint-cli2 --fix "**/*.md"
```

All checks should pass before the contribution is considered complete.

## Pull Requests

Keep pull requests focused.

For a new vulnerability rule, a typical PR should contain:

- the new guide;
- the nearest category index update;
- regenerated catalog output;
- allowlist changes if new reference domains are required;
- tests when repository tooling changes.

In the PR description, briefly explain:

- what security pattern is being added or changed;
- why it deserves a separate rule;
- which authoritative references support it;
- any known detection limitations or important false positives.

## Changes to the Rule Format

The guide format is shared infrastructure for humans, repository tooling, and future coding-agent integrations.

Avoid casually adding new metadata fields, changing required headings, or changing generated catalog structure.

Changes to the rule contract should explain:

1. what problem the change solves;
2. why existing fields or prose cannot represent it;
3. how existing rules will be migrated;
4. how validation and generated outputs will change.

## Contribution Philosophy

Web of Flaws is not intended to become a collection of grep rules.

The goal is to capture reusable security reasoning:

```text
candidate pattern
      ↓
trust boundary / dataflow analysis
      ↓
required exploitation conditions
      ↓
confirmed vulnerability
      ↓
appropriate remediation
```

A useful contribution should help both a developer and a coding agent understand not only **what looks dangerous**, but **why it is dangerous, when it is actually exploitable, and when it is safe**.
