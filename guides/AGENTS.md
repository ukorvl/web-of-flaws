# Guide Instructions

## Scope

This directory contains the source Markdown for the security-rule catalog. Category `README.md`
files are indexes; every rule *is exactly one Markdown file*.

## Rule Contract

- Start every rule with YAML frontmatter. Keep its stable `WOF-<FAMILY>-<NUMBER>` ID; never reuse
  an ID for a different flaw.
- Use one of `vulnerability`, `weakness`, or `hardening-gap` for `kind`. Treat severity and
  exploitability as rule-level defaults, not a verdict for every candidate match.
- Declare CWE and OWASP mappings under `standards`, then include canonical supporting URLs under
  `## References`.
- A `dataflow` rule declares `sources` and `sinks`, never `indicators`. A `semantic-pattern` rule
  declares `indicators`, never `sources` or `sinks`.
- Keep the required heading order mentioned in `.markdownlint-cli2.jsonc`.
- Use authoritative, allowlisted reference domains only. Add an allowlist entry only when the source
  is authoritative and its scope and purpose are clear.
- Update the nearest category index for a new guide or changed title. Notes are explanatory content,
  not rules: do not give them rule frontmatter or add them to the generated catalog.
- When you add a code example or snippet, check its syntax and correctness, make code self-explanatory, and avoid including secrets or sensitive data. Use a language-specific fenced code block with the correct language tag.
- Never add code blocks with an example that can be executed as a real attack as-is. If you need to demonstrate an exploit, use a safe, non-exploitable example or a mockup. On the other hand, never invent a vulnerability or weakness that does not exist in real-world software and make code examples close to real-world scenarios.
- Always ensure that a guide is easy to understand and follow by human readers. Use clear and concise language, and provide context for why the rule is important and how it can be applied in practice.
- There should be a clear separation between guides, never duplicate content across guides. If you find that a guide is too long or complex, consider breaking it into multiple guides with clear relationships and references. If you are unsure about the best way to structure a guide, report it directly and don't make assumptions about the best way to structure it

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
