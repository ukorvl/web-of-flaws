from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

if __package__:
    from .generate_catalog import build_rules
    from .guide_tools import (
        MARKDOWN_LINK_RE,
        URL_RE,
        GuideValidationError,
        is_guide_note_path,
        iter_guide_markdown_paths,
        iter_rendered_lines,
    )
else:
    from generate_catalog import build_rules
    from guide_tools import (
        MARKDOWN_LINK_RE,
        URL_RE,
        GuideValidationError,
        is_guide_note_path,
        iter_guide_markdown_paths,
        iter_rendered_lines,
    )

ROOT = Path(__file__).resolve().parents[1]
COMMAND = "python3 scripts/lint_repo.py"
ALLOWED_REFERENCE_DOMAINS_PATH = Path("catalog/allowed-reference-domains.json")
ALLOWED_REFERENCE_DOMAIN_SCOPES = {"guide-references", "example-urls"}
HOSTNAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
LOCAL_MARKDOWN_LINK_RE = re.compile(
    r"\[([^\]]+)\]\((?P<target>(?![a-z][a-z0-9+.-]*:|//)[^)\s]+\.md)(?:#[^)]+)?\)",
    re.IGNORECASE,
)
REFERENCE_STYLE_LINK_RE = re.compile(r"(?<!\!)\[[^\]]+\]\[[^\]]*\]")
REFERENCE_DEFINITION_RE = re.compile(r"^\s*\[[^\]]+\]:\s+\S+")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


class AllowedDomainsValidationError(ValueError):
    pass


def load_allowed_domains(root: Path) -> dict[str, set[str]]:
    config_path = root / ALLOWED_REFERENCE_DOMAINS_PATH
    display_path = ALLOWED_REFERENCE_DOMAINS_PATH.as_posix()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise AllowedDomainsValidationError(
            f"{display_path}: invalid JSON near line {error.lineno} column {error.colno}"
        ) from error

    errors: list[str] = []
    scopes: dict[str, set[str]] = {}
    seen_pairs: set[tuple[str, str]] = set()

    if not isinstance(raw, dict):
        raise AllowedDomainsValidationError(f"{display_path}: root must be a JSON object")

    schema_version = raw.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version != 1:
        errors.append(f"{display_path}: schema_version must equal 1")

    domains = raw.get("domains")
    if not isinstance(domains, list) or not domains:
        errors.append(f"{display_path}: domains must be a non-empty list")
        domains = []

    for index, entry in enumerate(domains):
        prefix = f"{display_path}: domains[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue

        domain = entry.get("domain")
        if not isinstance(domain, str) or not domain.strip():
            errors.append(f"{prefix}.domain must be a non-empty string")
            valid_domain = False
        else:
            valid_domain = domain == domain.strip() and domain == domain.lower() and bool(HOSTNAME_RE.fullmatch(domain))
            if not valid_domain:
                errors.append(f"{prefix}.domain must be a non-empty lowercase hostname")

        scopes_list = entry.get("scopes")
        if not isinstance(scopes_list, list) or not scopes_list:
            errors.append(f"{prefix}.scopes must be a non-empty list")
            scopes_list = []

        purpose = entry.get("purpose")
        if not isinstance(purpose, str) or not purpose.strip():
            errors.append(f"{prefix}.purpose must be a non-empty string")

        for scope_index, scope in enumerate(scopes_list):
            if not isinstance(scope, str) or not scope.strip():
                errors.append(f"{prefix}.scopes[{scope_index}] must be a non-empty string")
                continue
            if scope not in ALLOWED_REFERENCE_DOMAIN_SCOPES:
                errors.append(f"{prefix}.scopes[{scope_index}] must be one of: example-urls, guide-references")
                continue
            if not valid_domain:
                continue
            pair = (domain, scope)
            if pair in seen_pairs:
                errors.append(f"{display_path}: duplicate domain/scope combination for {domain!r} and {scope!r}")
                continue
            seen_pairs.add(pair)
            scopes.setdefault(scope, set()).add(domain)

    if errors:
        raise AllowedDomainsValidationError("\n".join(errors))
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


def strip_html_comments_preserve_lines(markdown: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return "".join("\n" if character == "\n" else " " for character in match.group(0))

    return HTML_COMMENT_RE.sub(replace, markdown)


def local_markdown_links(path: Path) -> list[tuple[str, int]]:
    links: list[tuple[str, int]] = []
    markdown = strip_html_comments_preserve_lines(path.read_text(encoding="utf-8"))
    for line_number, _stripped, scrubbed in iter_rendered_lines(markdown):
        for match in LOCAL_MARKDOWN_LINK_RE.finditer(scrubbed):
            links.append((match.group("target"), line_number))
    return links


def reference_style_markdown_lines(path: Path) -> list[int]:
    line_numbers: list[int] = []
    markdown = strip_html_comments_preserve_lines(path.read_text(encoding="utf-8"))
    for line_number, _stripped, scrubbed in iter_rendered_lines(markdown):
        if REFERENCE_STYLE_LINK_RE.search(scrubbed) or REFERENCE_DEFINITION_RE.search(scrubbed):
            line_numbers.append(line_number)
    return line_numbers


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
    guides_root = root / "guides"

    for readme in iter_guide_readme_paths(root):
        for line_number in reference_style_markdown_lines(readme):
            errors.append(
                f"{readme}:{line_number}: category indexes must use inline Markdown links, not reference-style links"
            )
        for target, line_number in local_markdown_links(readme):
            resolved = (readme.parent / target).resolve()
            if not resolved.exists() or not resolved.is_file():
                errors.append(f"{readme}:{line_number}: linked markdown target does not exist: {target}")
                continue
            counts[(readme.resolve(), resolved)] = counts.get((readme.resolve(), resolved), 0) + 1

    # TODO: Lint category README.md entries too; parent indexes can currently omit nested categories silently.
    for guide_path in iter_guide_markdown_paths(root):
        if guide_path.name == "README.md":
            continue

        nearest_readme = nearest_readme_for(guide_path, root)
        if nearest_readme is None:
            errors.append(f"{guide_path}: could not find nearest README.md index")
            continue

        count = counts.get((nearest_readme.resolve(), guide_path.resolve()), 0)
        if count != 1:
            relative_readme = nearest_readme.relative_to(root).as_posix()
            kind = "note" if is_guide_note_path(guide_path, guides_root) else "guide"
            errors.append(
                f"{guide_path}: nearest index {relative_readme} must link to this {kind} exactly once (found {count})"
            )

    return errors


def lint(root: Path) -> list[str]:
    errors: list[str] = []

    try:
        build_rules(root)
    except GuideValidationError as error:
        errors.extend(str(error).splitlines())

    errors.extend(lint_guide_indexes(root))

    try:
        allowed_domains = load_allowed_domains(root)
    except AllowedDomainsValidationError as error:
        errors.extend(str(error).splitlines())
    else:
        for path in iter_guide_markdown_paths(root):
            markdown = path.read_text(encoding="utf-8")
            for url, line_number, scope in rendered_urls_with_scopes(markdown):
                hostname = urlparse(url).hostname
                if not hostname:
                    errors.append(f"{path}:{line_number}: could not determine hostname for {url}")
                    continue
                if hostname not in allowed_domains.get(scope, set()):
                    errors.append(f"{path}:{line_number}: hostname {hostname!r} is not allowlisted for scope {scope!r}")
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
