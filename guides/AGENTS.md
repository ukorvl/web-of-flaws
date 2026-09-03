# Guide Instructions

## Scope

This directory contains the source Markdown for the security-rule catalog. Category `README.md`
files are indexes; every rule is exactly one Markdown file.

## Rule Contract

- Start every rule with YAML frontmatter. Keep its stable `WOF-<FAMILY>-<NUMBER>` ID; never reuse
  an ID for a different flaw.
- Use one of `vulnerability`, `weakness`, or `hardening-gap` for `kind`. Treat severity and
  exploitability as rule-level defaults, not a verdict for every candidate match.
- Declare CWE and OWASP mappings under `standards`, then include canonical supporting URLs under
  `## References`.
- A `dataflow` rule declares `sources` and `sinks`, never `indicators`. A `semantic-pattern` rule
  declares `indicators`, never `sources` or `sinks`.
- Keep the required heading order: `Rule`, `Mental Model`, `Why This Matters`, `Vulnerable Pattern`,
  `Example Attack`, `Why The Attack Works`, `Safer Pattern`, `Detection`, `False Positives`,
  `References`, and `Quick Checklist`. Optional sections appear before `References`.
- Use authoritative, allowlisted reference domains only. Add an allowlist entry only when the source
  is authoritative and its scope and purpose are clear.
- Update the nearest category index for a new guide or changed title. Notes are explanatory content,
  not rules: do not give them rule frontmatter or add them to the generated catalog.

## Generated Data

Guides are the source of truth. Never edit `catalog/rules.json` manually. After changing guide
metadata, run `python3 scripts/generate_catalog.py`. After changing guide groups, run
`python3 scripts/sync_guide_labels.py`.

## Required Checks

```bash
markdownlint-cli2
python3 scripts/check.py
```

Use `python3 scripts/check.py --check guides`, `--check catalog`, or `--check standards` only when
the change is deliberately limited to that invariant. Run the full command for a normal guide change.
