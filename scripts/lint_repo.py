from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse
import json
import re
import sys

from generate_catalog import build_rules
from guide_tools import (
    GuideValidationError,
    MARKDOWN_LINK_RE,
    URL_RE,
    iter_guide_rule_paths,
    iter_guide_markdown_paths,
    iter_rendered_lines,
)


ROOT = Path(__file__).resolve().parents[1]
COMMAND = "python3 scripts/lint_repo.py"
# TODO: Parse or reject reference-style local links; broken README refs can bypass this inline-link regex.
LOCAL_MARKDOWN_LINK_RE = re.compile(
    r"\[([^\]]+)\]\((?P<target>(?![a-z][a-z0-9+.-]*:|//)[^)\s]+\.md)(?:#[^)]+)?\)",
    re.IGNORECASE,
)


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


def iter_guide_readme_paths(root: Path) -> list[Path]:
    return sorted((root / "guides").rglob("README.md"))


def local_markdown_links(path: Path) -> list[tuple[str, int]]:
    links: list[tuple[str, int]] = []
    markdown = path.read_text(encoding="utf-8")
    for line_number, _stripped, scrubbed in iter_rendered_lines(markdown):
        for match in LOCAL_MARKDOWN_LINK_RE.finditer(scrubbed):
            links.append((match.group("target"), line_number))
    return links


def nearest_readme_for(path: Path, root: Path) -> Path | None:
    guides_root = root / "guides"
    current = path.parent
    while current == guides_root or guides_root in current.parents:
        candidate = current / "README.md"
        if candidate.exists():
            return candidate
        if current == guides_root:
            break
        current = current.parent
    return None


def lint_guide_indexes(root: Path) -> list[str]:
    errors: list[str] = []
    counts: dict[tuple[Path, Path], int] = {}

    for readme in iter_guide_readme_paths(root):
        for target, line_number in local_markdown_links(readme):
            resolved = (readme.parent / target).resolve()
            if not resolved.exists() or not resolved.is_file():
                errors.append(f"{readme}:{line_number}: linked markdown target does not exist: {target}")
                continue
            counts[(readme.resolve(), resolved)] = counts.get((readme.resolve(), resolved), 0) + 1

    # TODO: Lint category README.md entries too; parent indexes can currently omit nested categories silently.
    for rule_path in iter_guide_rule_paths(root):
        nearest_readme = nearest_readme_for(rule_path, root)
        if nearest_readme is None:
            errors.append(f"{rule_path}: could not find nearest README.md index")
            continue

        count = counts.get((nearest_readme.resolve(), rule_path.resolve()), 0)
        if count != 1:
            relative_readme = nearest_readme.relative_to(root).as_posix()
            errors.append(
                f"{rule_path}: nearest index {relative_readme} must link to this guide exactly once (found {count})"
            )

    return errors


def lint(root: Path) -> list[str]:
    errors: list[str] = []

    try:
        build_rules(root)
    except GuideValidationError as error:
        errors.extend(str(error).splitlines())

    errors.extend(lint_guide_indexes(root))

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
