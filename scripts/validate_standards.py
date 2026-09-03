from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__:
    from .guide_tools import CWE_ID_RE, OWASP_TOP_10_RE, GuideValidationError, iter_guide_rule_paths, load_guide
else:
    from guide_tools import CWE_ID_RE, OWASP_TOP_10_RE, GuideValidationError, iter_guide_rule_paths, load_guide

ROOT = Path(__file__).resolve().parents[1]
OWASP_2025_PATH = Path("catalog/standards/owasp-2025.json")


class StandardsValidationError(ValueError):
    pass


def load_owasp_2025(root: Path) -> dict[str, set[str]]:
    data_path = root / OWASP_2025_PATH
    display_path = OWASP_2025_PATH.as_posix()
    try:
        raw = json.loads(data_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise StandardsValidationError(f"{display_path}: file does not exist") from error
    except json.JSONDecodeError as error:
        raise StandardsValidationError(
            f"{display_path}: invalid JSON near line {error.lineno} column {error.colno}"
        ) from error

    errors: list[str] = []
    mappings: dict[str, set[str]] = {}
    if not isinstance(raw, dict) or not raw:
        raise StandardsValidationError(f"{display_path}: root must be a non-empty JSON object")

    for owasp, entry in raw.items():
        if not isinstance(owasp, str) or not OWASP_TOP_10_RE.fullmatch(owasp):
            errors.append(f"{display_path}: OWASP entry {owasp!r} must match ^A\\d{{2}}:\\d{{4}} .+$")
            continue
        if not isinstance(entry, dict) or set(entry) != {"cwes"}:
            errors.append(f"{display_path}: {owasp!r} must be an object containing only cwes")
            continue
        cwes = entry["cwes"]
        if not isinstance(cwes, list) or not cwes:
            errors.append(f"{display_path}: {owasp!r}.cwes must be a non-empty list")
            continue
        invalid_cwes = [cwe for cwe in cwes if not isinstance(cwe, str) or not CWE_ID_RE.fullmatch(cwe)]
        if invalid_cwes:
            errors.append(f"{display_path}: {owasp!r}.cwes contains invalid CWE values: {invalid_cwes}")
            continue
        if len(cwes) != len(set(cwes)):
            errors.append(f"{display_path}: {owasp!r}.cwes must not contain duplicates")
            continue
        mappings[owasp] = set(cwes)

    if errors:
        raise StandardsValidationError("\n".join(sorted(errors)))
    return mappings


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    try:
        mappings = load_owasp_2025(root)
    except StandardsValidationError as error:
        return str(error).splitlines()

    declared_cwes = set().union(*mappings.values())
    for path in iter_guide_rule_paths(root):
        try:
            frontmatter, _body = load_guide(path)
        except GuideValidationError as error:
            errors.append(str(error))
            continue

        standards = frontmatter.get("standards")
        if not isinstance(standards, dict):
            continue
        cwes = standards.get("cwe")
        owasp_entries = standards.get("owasp_top_10")
        if not isinstance(cwes, list) or not isinstance(owasp_entries, list):
            continue

        valid_cwes = [cwe for cwe in cwes if isinstance(cwe, str) and CWE_ID_RE.fullmatch(cwe)]
        valid_owasp_entries = [
            entry for entry in owasp_entries if isinstance(entry, str) and OWASP_TOP_10_RE.fullmatch(entry)
        ]

        for cwe in valid_cwes:
            if cwe not in declared_cwes:
                errors.append(f"{path}: standards.cwe entry {cwe!r} is not declared in {OWASP_2025_PATH}")
        for owasp in valid_owasp_entries:
            if owasp not in mappings:
                errors.append(f"{path}: standards.owasp_top_10 entry {owasp!r} is not declared in {OWASP_2025_PATH}")

        for owasp in valid_owasp_entries:
            allowed_cwes = mappings.get(owasp)
            if allowed_cwes is None:
                continue
            for cwe in valid_cwes:
                if cwe in declared_cwes and cwe not in allowed_cwes:
                    errors.append(
                        f"{path}: direct CWE/OWASP relationship {cwe!r} -> {owasp!r} is not declared in "
                        f"{OWASP_2025_PATH}"
                    )

    return sorted(errors)


def main() -> int:
    print("Validating guide standards integrity.")
    errors = validate(ROOT)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"Standards validation failed with {len(errors)} error(s).", file=sys.stderr)
        return 1
    print("Standards validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
