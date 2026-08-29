from __future__ import annotations

import re
from pathlib import Path

GUIDE_RULE_KEYS = {
    "id",
    "title",
    "kind",
    "default_severity",
    "exploitability",
    "standards",
    "platforms",
    "languages",
    "detection",
    "sources",
    "sinks",
    "indicators",
    "tags",
}
GUIDE_KINDS = {"vulnerability", "weakness", "hardening-gap"}
GUIDE_DEFAULT_SEVERITIES = {"low", "medium", "high", "critical"}
GUIDE_EXPLOITABILITY = {"low", "medium", "high"}
STANDARDS_KEYS = {"cwe", "owasp_top_10"}
GUIDE_PLATFORMS = {
    "browser",
    "server",
    "mobile",
    "desktop",
    "ci-cd",
    "infrastructure",
    "cloud",
    "container",
}
GUIDE_LANGUAGES = {
    "html",
    "javascript",
    "typescript",
    "yaml",
    "dotenv",
    "json",
    "css",
    "python",
    "shell",
    "bash",
    "sql",
    "terraform",
}
DETECTION_TYPES = {"dataflow", "semantic-pattern"}
DETECTION_METHODS = {"grep", "ast", "taint-analysis", "semantic-review", "entropy-analysis"}
DETECTION_KEYS = {"type", "methods", "candidate_tokens"}
CWE_ID_RE = re.compile(r"^CWE-\d+$")
OWASP_TOP_10_RE = re.compile(r"^([AX]\d{2}):(\d{4}) (.+)$")
URL_RE = re.compile(r"(?:https?:)?//[^\s)>`]+", re.IGNORECASE)
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\(((?:https?:)?//[^)\s]+)\)", re.IGNORECASE)
CODE_FENCE_RE = re.compile(r"^([`~]{3,})")
INLINE_CODE_RE = re.compile(r"(?P<fence>`+).*?(?P=fence)")
LEADING_YAML_INDICATOR_RE = re.compile(r"^(?:[#&*!@`|>]|%|[{}\[\],]|(?:\?|-)(?=\s))")
PLAIN_SCALAR_SYNTAX_RE = re.compile(r":(?=\s|$)|\s#")


class GuideValidationError(ValueError):
    pass


def iter_guide_rule_paths(root: Path) -> list[Path]:
    return sorted(path for path in (root / "guides").rglob("*.md") if path.name != "README.md")


def iter_guide_markdown_paths(root: Path) -> list[Path]:
    return sorted((root / "guides").rglob("*.md"))


def load_guide(path: Path) -> tuple[dict, str]:
    text = path.read_text(encoding="utf-8")
    frontmatter_text, body = split_frontmatter(text, path)
    return parse_yaml_mapping(frontmatter_text, path), body


def split_frontmatter(text: str, path: Path) -> tuple[str, str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise GuideValidationError(f"{path}: guide is missing YAML frontmatter")

    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            return "\n".join(lines[1:index]), "\n".join(lines[index + 1 :])

    raise GuideValidationError(f"{path}: guide frontmatter is not closed")


def parse_yaml_mapping(text: str, path: Path) -> dict:
    lines = [line.rstrip() for line in text.splitlines()]
    index = 0

    def next_nonblank(start: int) -> int:
        while start < len(lines) and not lines[start].strip():
            start += 1
        return start

    def parse_scalar(value: str, line_number: int) -> str:
        value = value.strip()
        if value[:1] in {'"', "'"}:
            if value[-1:] != value[:1]:
                raise GuideValidationError(f"{path}: unsupported quoted YAML scalar near line {line_number}")
            return value[1:-1]
        if LEADING_YAML_INDICATOR_RE.search(value) or PLAIN_SCALAR_SYNTAX_RE.search(value):
            raise GuideValidationError(
                f"{path}: unsupported plain YAML scalar near line {line_number}; quote parser-sensitive values"
            )
        return value

    def parse_list(indent: int) -> list:
        nonlocal index
        items = []
        while index < len(lines):
            index = next_nonblank(index)
            if index >= len(lines):
                break
            line = lines[index]
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent < indent:
                break
            if current_indent != indent or not line.lstrip().startswith("- "):
                raise GuideValidationError(f"{path}: unsupported YAML list structure near line {index + 1}")
            value = line.lstrip()[2:]
            index += 1
            if value:
                items.append(parse_scalar(value, index))
            else:
                items.append(parse_node(indent + 2))
        return items

    def parse_mapping(indent: int) -> dict:
        nonlocal index
        result = {}
        while index < len(lines):
            index = next_nonblank(index)
            if index >= len(lines):
                break
            line = lines[index]
            current_indent = len(line) - len(line.lstrip(" "))
            if current_indent < indent:
                break
            if current_indent != indent or line.lstrip().startswith("- "):
                raise GuideValidationError(f"{path}: unsupported YAML mapping structure near line {index + 1}")
            key, separator, remainder = line.strip().partition(":")
            if not separator:
                raise GuideValidationError(f"{path}: invalid YAML mapping near line {index + 1}")
            if key in result:
                raise GuideValidationError(f"{path}: duplicate YAML key {key!r}")
            index += 1
            result[key] = parse_scalar(remainder, index) if remainder.strip() else parse_node(indent + 2)
        return result

    def parse_node(indent: int):
        nonlocal index
        index = next_nonblank(index)
        if index >= len(lines):
            return {}
        line = lines[index]
        current_indent = len(line) - len(line.lstrip(" "))
        if current_indent < indent:
            return {}
        return parse_list(indent) if line.lstrip().startswith("- ") else parse_mapping(indent)

    parsed = parse_mapping(0)
    if not isinstance(parsed, dict):
        raise GuideValidationError(f"{path}: frontmatter root must be a mapping")
    return parsed


def parse_references(body: str) -> list[dict[str, str]]:
    references = []
    in_references = False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped == "## References":
            in_references = True
            continue
        if in_references and stripped.startswith("## "):
            break
        if not in_references:
            continue
        match = MARKDOWN_LINK_RE.search(stripped)
        if match:
            references.append({"label": match.group(1), "url": match.group(2)})
    return references


def rendered_urls(markdown: str) -> list[tuple[str, int]]:
    urls: list[tuple[str, int]] = []
    for line_number, _stripped, scrubbed in iter_rendered_lines(markdown):
        for match in MARKDOWN_LINK_RE.finditer(scrubbed):
            urls.append((match.group(2), line_number))
        without_links = MARKDOWN_LINK_RE.sub("", scrubbed)
        for match in URL_RE.finditer(without_links):
            urls.append((match.group(0), line_number))
    return urls


def iter_rendered_lines(markdown: str):
    fence: tuple[str, int] | None = None
    for line_number, line in enumerate(markdown.splitlines(), start=1):
        stripped = line.strip()
        next_fence = update_code_fence_state(stripped, fence)
        if next_fence != fence:
            fence = next_fence
            continue
        if fence:
            continue
        yield line_number, stripped, INLINE_CODE_RE.sub("", line)


def update_code_fence_state(
    stripped: str,
    fence: tuple[str, int] | None,
) -> tuple[str, int] | None:
    match = CODE_FENCE_RE.match(stripped)
    if not match:
        return fence

    marker = match.group(1)
    if fence is None:
        return marker[0], len(marker)
    if marker[0] == fence[0] and len(marker) >= fence[1]:
        return None
    return fence


def validate_frontmatter(frontmatter: dict, path: Path) -> list[str]:
    errors = []

    extra_keys = sorted(set(frontmatter) - GUIDE_RULE_KEYS)
    if extra_keys:
        errors.append(f"{path}: unexpected frontmatter keys: {', '.join(extra_keys)}")

    for key in (
        "id",
        "title",
        "kind",
        "default_severity",
        "exploitability",
        "standards",
        "platforms",
        "languages",
        "detection",
        "tags",
    ):
        if key not in frontmatter:
            errors.append(f"{path}: missing frontmatter key {key}")

    rule_id = validate_required_string(frontmatter.get("id"), path, "id", errors)
    if rule_id is not None and not re.fullmatch(r"WOF-[A-Z0-9]+-\d{3}", rule_id):
        errors.append(f"{path}: id must match ^WOF-[A-Z0-9]+-\\d{{3}}$")

    validate_required_string(frontmatter.get("title"), path, "title", errors)

    kind = validate_required_string(frontmatter.get("kind"), path, "kind", errors)
    if kind is not None and kind not in GUIDE_KINDS:
        errors.append(f"{path}: kind must be one of {sorted(GUIDE_KINDS)}")

    default_severity = validate_required_string(
        frontmatter.get("default_severity"),
        path,
        "default_severity",
        errors,
    )
    if default_severity is not None and default_severity not in GUIDE_DEFAULT_SEVERITIES:
        errors.append(f"{path}: default_severity must be one of {sorted(GUIDE_DEFAULT_SEVERITIES)}")

    exploitability = validate_required_string(
        frontmatter.get("exploitability"),
        path,
        "exploitability",
        errors,
    )
    if exploitability is not None and exploitability not in GUIDE_EXPLOITABILITY:
        errors.append(f"{path}: exploitability must be one of {sorted(GUIDE_EXPLOITABILITY)}")

    errors.extend(validate_string_list(frontmatter.get("platforms"), GUIDE_PLATFORMS, path, "platforms"))
    errors.extend(validate_string_list(frontmatter.get("languages"), GUIDE_LANGUAGES, path, "languages"))

    tags = frontmatter.get("tags")
    if not isinstance(tags, list) or not tags:
        errors.append(f"{path}: tags must be a non-empty list")
    else:
        for tag in tags:
            if not isinstance(tag, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", tag):
                errors.append(f"{path}: tag {tag!r} must be lowercase-kebab-case")

    standards = frontmatter.get("standards")
    if not isinstance(standards, dict):
        errors.append(f"{path}: standards must be a mapping")
    else:
        extra_standards_keys = sorted(set(standards) - STANDARDS_KEYS)
        if extra_standards_keys:
            errors.append(f"{path}: unexpected standards keys: {', '.join(extra_standards_keys)}")

        cwes = standards.get("cwe")
        if not isinstance(cwes, list) or not cwes:
            errors.append(f"{path}: standards.cwe must be a non-empty list")
        else:
            for cwe in cwes:
                if not isinstance(cwe, str) or not CWE_ID_RE.fullmatch(cwe):
                    errors.append(f"{path}: CWE value {cwe!r} must match ^CWE-\\d+$")

        owasp = standards.get("owasp_top_10")
        if not isinstance(owasp, list) or not owasp:
            errors.append(f"{path}: standards.owasp_top_10 must be a non-empty list")
        else:
            for entry in owasp:
                if not isinstance(entry, str) or not OWASP_TOP_10_RE.fullmatch(entry):
                    errors.append(f"{path}: OWASP Top 10 value {entry!r} must match ^[AX]\\d{{2}}:\\d{{4}} .+$")

    detection = frontmatter.get("detection")
    if not isinstance(detection, dict):
        errors.append(f"{path}: detection must be a mapping")
        return errors

    extra_detection_keys = sorted(set(detection) - DETECTION_KEYS)
    if extra_detection_keys:
        errors.append(f"{path}: unexpected detection keys: {', '.join(extra_detection_keys)}")

    detection_type = detection.get("type")
    if detection_type not in DETECTION_TYPES:
        errors.append(f"{path}: detection.type must be one of {sorted(DETECTION_TYPES)}")

    methods = detection.get("methods")
    if not isinstance(methods, list) or not methods:
        errors.append(f"{path}: detection.methods must be a non-empty list")
    else:
        for method in methods:
            if not isinstance(method, str) or not method.strip():
                errors.append(f"{path}: detection.methods entries must be non-empty strings")
            elif method not in DETECTION_METHODS:
                errors.append(f"{path}: detection method {method!r} must be one of {sorted(DETECTION_METHODS)}")

    candidate_tokens = detection.get("candidate_tokens")
    if candidate_tokens is not None:
        if not isinstance(candidate_tokens, list) or not candidate_tokens:
            errors.append(f"{path}: detection.candidate_tokens must be a non-empty list")
        else:
            for token in candidate_tokens:
                if not isinstance(token, str) or not token.strip():
                    errors.append(f"{path}: detection.candidate_tokens entries must be non-empty strings")

    if detection_type == "dataflow":
        errors.extend(
            validate_non_empty_string_list(
                frontmatter.get("sources"),
                path,
                "sources",
                "dataflow guides must declare non-empty sources",
            )
        )
        errors.extend(
            validate_non_empty_string_list(
                frontmatter.get("sinks"),
                path,
                "sinks",
                "dataflow guides must declare non-empty sinks",
            )
        )
        if "indicators" in frontmatter:
            errors.append(f"{path}: dataflow guides must not declare indicators")
    elif detection_type == "semantic-pattern":
        errors.extend(
            validate_non_empty_string_list(
                frontmatter.get("indicators"),
                path,
                "indicators",
                "semantic-pattern guides must declare non-empty indicators",
            )
        )
        if "sources" in frontmatter:
            errors.append(f"{path}: semantic-pattern guides must not declare sources")
        if "sinks" in frontmatter:
            errors.append(f"{path}: semantic-pattern guides must not declare sinks")

    return errors


def validate_string_list(value: object, allowed: set[str], path: Path, field: str) -> list[str]:
    errors = []
    if not isinstance(value, list) or not value:
        return [f"{path}: {field} must be a non-empty list"]
    for item in value:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{path}: {field} entries must be non-empty strings")
        elif item not in allowed:
            errors.append(f"{path}: {field} value {item!r} must be one of {sorted(allowed)}")
    return errors


def validate_required_string(
    value: object,
    path: Path,
    field: str,
    errors: list[str],
) -> str | None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path}: {field} must be a non-empty string")
        return None
    return value


def validate_non_empty_string_list(
    value: object,
    path: Path,
    field: str,
    missing_message: str,
) -> list[str]:
    if not isinstance(value, list) or not value:
        return [f"{path}: {missing_message}"]

    errors = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{path}: {field} entries must be non-empty strings")
    return errors
