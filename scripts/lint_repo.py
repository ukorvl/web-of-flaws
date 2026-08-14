from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
import json
import sys

from generate_catalog import build_rules
from guide_tools import (
    GuideValidationError,
    MARKDOWN_LINK_RE,
    URL_RE,
    iter_guide_markdown_paths,
    iter_rendered_lines,
)


ROOT = Path(__file__).resolve().parents[1]
COMMAND = "python3 scripts/lint_repo.py"


def load_allowed_domains(root: Path) -> dict[str, set[str]]:
    raw = json.loads((root / "catalog" / "allowed-reference-domains.json").read_text(encoding="utf-8"))
    scopes: dict[str, set[str]] = {}
    for entry in raw.get("domains", []):
        domain = entry["domain"]
        for scope in entry.get("scopes", []):
            scopes.setdefault(scope, set()).add(domain)
    return scopes


def rendered_urls_with_scopes(markdown: str) -> list[tuple[str, int, str]]:
    urls: list[tuple[str, int, str]] = []
    section = ""

    for line_number, stripped, scrubbed in iter_rendered_lines(markdown):
        if stripped.startswith("## "):
            section = stripped[3:].strip()

        scope = "guide-references" if section == "References" else "example-urls"
        for match in MARKDOWN_LINK_RE.finditer(scrubbed):
            urls.append((match.group(2), line_number, scope))
        for match in URL_RE.finditer(MARKDOWN_LINK_RE.sub("", scrubbed)):
            urls.append((match.group(0), line_number, scope))
    return urls


def lint(root: Path) -> list[str]:
    errors: list[str] = []

    try:
        build_rules(root)
    except GuideValidationError as error:
        errors.extend(str(error).splitlines())

    allowed_domains = load_allowed_domains(root)
    for path in iter_guide_markdown_paths(root):
        markdown = path.read_text(encoding="utf-8")
        for url, line_number, scope in rendered_urls_with_scopes(markdown):
            hostname = urlparse(url).hostname
            if not hostname:
                errors.append(f"{path}:{line_number}: could not determine hostname for {url}")
                continue
            if hostname not in allowed_domains.get(scope, set()):
                errors.append(
                    f"{path}:{line_number}: hostname {hostname!r} is not allowlisted for scope {scope!r}"
                )
    return sorted(set(errors))


def main() -> int:
    print("Linting guide metadata and allowlisted rendered URLs.")
    errors = lint(ROOT)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        print(f"Repository lint failed with {len(errors)} error(s).", file=sys.stderr)
        return 1
    print("Repository lint passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
