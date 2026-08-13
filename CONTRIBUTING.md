# Contributing

## Getting started

- Run `npx markdownlint-cli2 "**/*.md"` before sending changes.
- If you touched several Markdown files, prefer `npx markdownlint-cli2 --fix "**/*.md"` and then review the result manually.
- Keep examples concise, self-contained, and easy to parse for both humans and agents.

## Guide schema

Each guide under `guides/` except category `README.md` files must start with YAML frontmatter.
Use this frontmatter as the stable machine-readable index for the rule:

```yaml
---
id: WOF-XSS-001
title: URL-derived Input to HTML Sink (innerHTML)
kind: vulnerability
severity: high
exploitability: high
standards:
  cwe:
    - CWE-79
  owasp_top_10:
    - A05:2025 Injection
platforms:
  - browser
languages:
  - html
  - javascript
detection:
  type: dataflow
  methods:
    - grep
    - ast
    - taint-analysis
    - semantic-review
sources:
  - window.location.search
sinks:
  - Element.innerHTML
tags:
  - xss
---
```

### Required frontmatter fields

- `id`: stable rule ID. Never recycle or silently change an existing published ID.
- `title`: human-readable rule title.
- `kind`: use `vulnerability`, `weakness`, or `hardening`.
- `severity`: impact if the issue is real.
- `exploitability`: how practical exploitation is once preconditions are met.
- `standards`: include at least one CWE mapping, and include an OWASP mapping when there is a reasonable fit.
- `platforms`: where the rule applies, for example `browser`, `server`, `ci-cd`, or `infrastructure`.
- `languages`: the main languages or config formats used in the examples.
- `detection`: describe the primary analysis style and the methods that can find candidates.
- `tags`: short search terms.

### Detection-specific fields

- Dataflow rules should include `sources` and `sinks`.
- Pattern or review rules should include `indicators` instead of forcing fake `sources` and `sinks`.
- Do not try to encode the entire detection algorithm in YAML. The frontmatter is an index, not a programming language.

## Markdown structure

Guide bodies should follow this section order:

1. `## Rule`
2. `## Mental Model`
3. `## Why This Matters`
4. `## Vulnerable Pattern`
5. `## Example Attack`
6. `## Why The Attack Works`
7. `## Safer Pattern`
8. `## Detection`
9. `## False Positives`
10. Optional notes such as `## Framework Notes` or `## Scope Notes`
11. `## References`
12. `## Quick Checklist`

## References and provenance

- Every rule must have a `## References` section.
- Prefer primary or official sources such as MITRE CWE, OWASP, MDN, framework documentation, language standards, and vendor docs.
- Do not invent vulnerabilities, mappings, or claims about exploitability.
- If a rule makes an operational recommendation, make sure the references support the recommendation or clearly frame it as a local practice choice.

## Catalog and eval fixtures

- Update [catalog/rules.json](catalog/rules.json) whenever you add, remove, rename, or move a rule.
- Update [evals/fixtures.json](evals/fixtures.json) whenever you add or change a rule.
- Each rule should have at least one positive fixture and one negative fixture.
- Positive fixtures should demonstrate a candidate that should be reported.
- Negative fixtures should demonstrate a superficially similar pattern that should not be reported.

## Reporting philosophy

- A scanner should find candidates.
- An agent or reviewer should confirm whether the candidate is a real vulnerability, weakness, or hardening gap.
- Use the `False Positives` section to document where naive automation will over-report.
- Do not collapse `severity` and `exploitability` into a single field. They answer different questions.

## Adding or changing guides

- Update the nearest category `README.md` when you add or move a guide.
- Update the root [README.md](README.md) when you add a new category or a new top-level support file worth surfacing.
- Keep filenames parallel with related guides so similar cases are easy to compare.
- If you change a rule's meaning enough to break downstream references, create a new ID instead of mutating the old one into a different rule.
