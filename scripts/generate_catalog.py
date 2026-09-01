from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from guide_tools import (
    CWE_ID_RE,
    OWASP_TOP_10_RE,
    GuideValidationError,
    iter_guide_rule_paths,
    load_guide,
    parse_references,
    validate_frontmatter,
)

ROOT = Path(__file__).resolve().parents[1]
COMMAND = "python3 scripts/generate_catalog.py"


def catalog_path(root: Path) -> Path:
    return root / "catalog" / "rules.json"


def canonical_reference_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"


def expected_cwe_reference(cwe_id: str) -> str | None:
    match = CWE_ID_RE.fullmatch(cwe_id)
    if not match:
        return None
    return f"https://cwe.mitre.org/data/definitions/{cwe_id.removeprefix('CWE-')}.html"


def expected_owasp_top_10_reference(entry: str) -> str | None:
    match = OWASP_TOP_10_RE.fullmatch(entry)
    if not match:
        return None
    category, year, title = match.groups()
    if category.startswith("X"):
        # OWASP 2025 "Next Steps" entries currently share one canonical page.
        return f"https://owasp.org/Top10/{year}/X01_{year}-Next_Steps/"
    title_slug = re.sub(r"\s+", "_", title.strip())
    return f"https://owasp.org/Top10/{year}/{category}_{year}-{title_slug}/"


def validate_standard_references(
    frontmatter: dict,
    references: list[dict[str, str]],
    path: Path,
) -> list[str]:
    errors: list[str] = []
    standards = frontmatter.get("standards")
    if not isinstance(standards, dict):
        return errors

    reference_urls = {
        canonical_reference_url(reference["url"])
        for reference in references
        if isinstance(reference, dict) and isinstance(reference.get("url"), str)
    }

    for cwe_id in standards.get("cwe", []):
        if not isinstance(cwe_id, str):
            continue
        expected = expected_cwe_reference(cwe_id)
        if expected and expected not in reference_urls:
            errors.append(f"{path}: standards.cwe entry {cwe_id!r} must have matching reference {expected}")

    for entry in standards.get("owasp_top_10", []):
        if not isinstance(entry, str):
            continue
        expected = expected_owasp_top_10_reference(entry)
        if expected and expected not in reference_urls:
            errors.append(f"{path}: standards.owasp_top_10 entry {entry!r} must have matching reference {expected}")

    return errors


def build_rules(root: Path) -> list[dict]:
    errors: list[str] = []
    rules: list[dict] = []
    seen_ids: dict[str, str] = {}

    for path in iter_guide_rule_paths(root):
        frontmatter, body = load_guide(path)
        errors.extend(validate_frontmatter(frontmatter, path))

        references = parse_references(body)
        if not references:
            errors.append(f"{path}: guide must declare at least one reference under ## References")
        else:
            errors.extend(validate_standard_references(frontmatter, references, path))

        relative_path = path.relative_to(root).as_posix()
        rule_id = frontmatter.get("id")
        if isinstance(rule_id, str):
            previous = seen_ids.get(rule_id)
            if previous:
                errors.append(f"duplicate rule id {rule_id!r}: {previous} and {relative_path}")
            else:
                seen_ids[rule_id] = relative_path

        rule = {}
        for key, value in frontmatter.items():
            rule[key] = value
            if key == "id":
                rule["path"] = relative_path
        if "path" not in rule:
            rule["path"] = relative_path
        rule["references"] = references
        rules.append(rule)

    if errors:
        raise GuideValidationError("\n".join(sorted(errors)))

    return sorted(rules, key=lambda rule: rule["path"])


def render_catalog(root: Path) -> str:
    payload = {
        "schema_version": 1,
        "rules": build_rules(root),
    }
    return f"{json.dumps(payload, indent=2, ensure_ascii=False)}\n"


def main() -> int:
    check = "--check" in sys.argv
    destination = catalog_path(ROOT)
    mode = "Checking" if check else "Generating"
    current = destination.read_text(encoding="utf-8") if destination.exists() else ""

    try:
        rendered = render_catalog(ROOT)
    except GuideValidationError as error:
        print(str(error), file=sys.stderr)
        print("Catalog generation failed due to invalid guide metadata.", file=sys.stderr)
        return 1

    rules = json.loads(rendered)["rules"]
    print(f"{mode} catalog/rules.json for {len(rules)} rules.")

    if check:
        if current != rendered:
            print("catalog/rules.json is out of date. Run: python3 scripts/generate_catalog.py", file=sys.stderr)
            return 1
        print("catalog/rules.json is up to date.")
        return 0

    if current != rendered:
        destination.write_text(rendered, encoding="utf-8")
        print("Updated catalog/rules.json.")
    else:
        print("catalog/rules.json is already up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
