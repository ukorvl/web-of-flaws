from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

if __package__:
    from .guide_tools import MARKDOWN_LINK_RE, URL_RE, iter_guide_markdown_paths, iter_rendered_lines
else:
    from guide_tools import MARKDOWN_LINK_RE, URL_RE, iter_guide_markdown_paths, iter_rendered_lines

ROOT = Path(__file__).resolve().parents[1]
COMMAND = "python3 scripts/sync_reference_domains.py"
ALLOWED_REFERENCE_DOMAINS_PATH = Path("catalog/allowed-reference-domains.json")
ALLOWED_REFERENCE_DOMAIN_SCOPES = {"guide-references", "example-urls"}
HOSTNAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DEFAULT_CONFIG = {
    "schema_version": 1,
    "policy": {
        "default_action": "deny",
        "requirements": [
            "Every new external link added under guides/ must use an allowlisted domain.",
            "Review every generated domain addition and keep only authoritative sources or reserved example hosts.",
            "Every new or changed external URL added under guides/ must be opened and verified to resolve to the intended document.",
            "Prefer canonical destination URLs for guide references over links that only work through redirects.",
        ],
    },
    "domains": [],
}


class AllowedDomainsValidationError(ValueError):
    pass


def load_allowed_domains_config(root: Path) -> dict:
    config_path = root / ALLOWED_REFERENCE_DOMAINS_PATH
    display_path = ALLOWED_REFERENCE_DOMAINS_PATH.as_posix()
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise AllowedDomainsValidationError(f"{display_path}: file does not exist") from error
    except json.JSONDecodeError as error:
        raise AllowedDomainsValidationError(
            f"{display_path}: invalid JSON near line {error.lineno} column {error.colno}"
        ) from error

    errors: list[str] = []
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

        scopes = entry.get("scopes")
        if not isinstance(scopes, list) or not scopes:
            errors.append(f"{prefix}.scopes must be a non-empty list")
            scopes = []

        purpose = entry.get("purpose")
        if not isinstance(purpose, str) or not purpose.strip():
            errors.append(f"{prefix}.purpose must be a non-empty string")

        for scope_index, scope in enumerate(scopes):
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

    if errors:
        raise AllowedDomainsValidationError("\n".join(errors))
    return raw


def load_allowed_domains(root: Path) -> dict[str, set[str]]:
    scopes: dict[str, set[str]] = {}
    config = load_allowed_domains_config(root)
    for entry in config["domains"]:
        for scope in entry["scopes"]:
            scopes.setdefault(scope, set()).add(entry["domain"])
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


def collect_domain_scopes(root: Path) -> dict[str, set[str]]:
    domains: dict[str, set[str]] = {}
    errors: list[str] = []
    for path in iter_guide_markdown_paths(root):
        markdown = path.read_text(encoding="utf-8")
        for url, line_number, scope in rendered_urls_with_scopes(markdown):
            hostname = urlparse(url).hostname
            if not hostname:
                errors.append(f"{path}:{line_number}: could not determine hostname for {url}")
                continue
            domains.setdefault(hostname, set()).add(scope)

    if errors:
        raise AllowedDomainsValidationError("\n".join(sorted(errors)))
    return domains


def default_purpose(domain: str, scopes: set[str]) -> str:
    if scopes == {"example-urls"}:
        return f"Host {domain} used for non-live examples in repository guides."
    if scopes == {"guide-references"}:
        return f"Documentation hosted at {domain} and referenced by repository guides."
    return f"Host {domain} used by repository guide references and examples."


def render_allowed_domains(root: Path) -> str:
    config_path = root / ALLOWED_REFERENCE_DOMAINS_PATH
    config = load_allowed_domains_config(root) if config_path.exists() else dict(DEFAULT_CONFIG)
    existing_purposes = {
        entry["domain"]: entry["purpose"]
        for entry in config["domains"]
        if isinstance(entry, dict) and isinstance(entry.get("domain"), str) and isinstance(entry.get("purpose"), str)
    }
    domains = collect_domain_scopes(root)
    config["schema_version"] = DEFAULT_CONFIG["schema_version"]
    config["policy"] = DEFAULT_CONFIG["policy"]
    config["domains"] = [
        {
            "domain": domain,
            "scopes": sorted(scopes),
            "purpose": existing_purposes.get(domain, default_purpose(domain, scopes)),
        }
        for domain, scopes in sorted(domains.items())
    ]
    return f"{json.dumps(config, indent=2, ensure_ascii=False)}\n"


def main() -> int:
    check = "--check" in sys.argv
    destination = ROOT / ALLOWED_REFERENCE_DOMAINS_PATH
    current = destination.read_text(encoding="utf-8") if destination.exists() else ""

    try:
        rendered = render_allowed_domains(ROOT)
    except AllowedDomainsValidationError as error:
        print(str(error), file=sys.stderr)
        print("Reference domain synchronization failed.", file=sys.stderr)
        return 1

    domain_count = len(json.loads(rendered)["domains"])
    mode = "Checking" if check else "Syncing"
    print(f"{mode} reference domain allowlist for {domain_count} domains.")

    if check:
        if current != rendered:
            print(f"{ALLOWED_REFERENCE_DOMAINS_PATH} is out of date. Run: {COMMAND}", file=sys.stderr)
            return 1
        print(f"{ALLOWED_REFERENCE_DOMAINS_PATH} is up to date.")
        return 0

    if current != rendered:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8")
        print(f"Updated {ALLOWED_REFERENCE_DOMAINS_PATH}.")
    else:
        print(f"{ALLOWED_REFERENCE_DOMAINS_PATH} is already up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
