# Catalog Instructions

## Scope

This directory holds machine-readable catalog data, reference-domain policy, and security-standard
mappings consumed by the validation scripts.

## Data Ownership

- `rules.json` is generated from `guides/`; never edit it by hand. Regenerate it with
  `python3 scripts/generate_catalog.py` after changing guide metadata.
- `allowed-reference-domains.json` is synchronized from rendered URLs under `guides/`; run
  `python3 scripts/sync_reference_domains.py` after changing referenced domains. Review every added
  domain for authority and scope, and refine its generated purpose when useful. Do not keep broad
  exceptions merely to silence link validation.
- `standards/*` is generated from guide frontmatter; run `python3 scripts/validate_standards.py`
  after changing `standards` metadata.

## Required Checks

```bash
python3 scripts/check.py --check catalog
python3 scripts/check.py --check domains
python3 scripts/check.py --check guides
python3 scripts/check.py --check standards
```

When changing catalog validation behavior, also run `python3 -m unittest discover -s scripts/tests -v`.
