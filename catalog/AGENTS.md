# Catalog Instructions

## Scope

This directory holds machine-readable catalog data, reference-domain policy, and security-standard
mappings consumed by the validation scripts.

## Data Ownership

- `rules.json` is generated from `guides/`; never edit it by hand. Regenerate it with
  `python3 scripts/generate_catalog.py` after changing guide metadata.
- `allowed-reference-domains.json` is maintained source data. Add only authoritative domains, with
  a narrow scope and a clear purpose. Do not add broad exceptions merely to silence link validation.
- `standards/owasp-2025.json` is trusted semantic data. Each OWASP entry must use valid, unique CWE
  identifiers. A guide's direct CWE/OWASP relationship must exist in this mapping.

## Required Checks

```bash
python3 scripts/check.py --check catalog
python3 scripts/check.py --check guides
python3 scripts/check.py --check standards
```

When changing catalog validation behavior, also run `python3 -m unittest discover -s scripts/tests -v`.
