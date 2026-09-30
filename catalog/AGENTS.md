# Catalog Instructions

## Scope

This directory holds machine-readable catalog data, reference-domain policy, and security-standard
mappings consumed by the validation scripts.

## Data Ownership

- `rules.json` is generated from `guides/`; never edit it by hand. Regenerate it with
  `pnpm generate:catalog` after changing guide metadata.
- `allowed-reference-domains.json` is maintained source data. Add only authoritative domains, with
  a narrow scope and a clear purpose. Do not add broad exceptions merely to silence link validation.
- `standards/*` sets a list of security standards.

## Required Checks

```bash
pnpm check --check catalog
pnpm check --check guides
pnpm check --check standards
```

When changing catalog validation behavior, also run `pnpm test`.
