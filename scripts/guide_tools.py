from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

CWE_ID_RE = re.compile(r"^CWE-\d+$")
OWASP_TOP_10_RE = re.compile(r"^(A\d{2}):(\d{4}) (.+)$")
URL_RE = re.compile(r"(?:https?:)?//[^\s)>`]+", re.IGNORECASE)
MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\(((?:https?:)?//[^)\s]+)\)", re.IGNORECASE)
CODE_FENCE_RE = re.compile(r"^([`~]{3,})")
INLINE_CODE_RE = re.compile(r"(?P<fence>`+).*?(?P=fence)")
NOTES_DIRECTORY_NAME = "notes"
ROOT = Path(__file__).resolve().parents[1]
FRONTMATTER_SCHEMA_PATH = ROOT / "catalog" / "guide-frontmatter.schema.json"
FRONTMATTER_VALIDATOR = Draft202012Validator(json.loads(FRONTMATTER_SCHEMA_PATH.read_text(encoding="utf-8")))


class GuideValidationError(ValueError):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def construct_mapping_with_unique_keys(
    loader: UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict:
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.YAMLError(f"duplicate key {key!r} near line {key_node.start_mark.line + 1}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping_with_unique_keys)


def is_guide_note_path(path: Path, guides_root: Path | None = None) -> bool:
    relative = path.relative_to(guides_root) if guides_root is not None else path
    return NOTES_DIRECTORY_NAME in relative.parts


def iter_guide_rule_paths(root: Path) -> list[Path]:
    guides_root = root / "guides"
    return sorted(
        path
        for path in guides_root.rglob("*.md")
        if path.name != "README.md" and not is_guide_note_path(path, guides_root)
    )


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
    try:
        parsed = yaml.load(text, Loader=UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise GuideValidationError(f"{path}: invalid YAML frontmatter: {error}") from error
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
    validation_errors = sorted(
        FRONTMATTER_VALIDATOR.iter_errors(frontmatter),
        key=lambda error: (list(error.absolute_path), error.message),
    )
    errors = []
    for error in validation_errors:
        location = ".".join(str(part) for part in error.absolute_path)
        suffix = f" at {location}" if location else ""
        errors.append(f"{path}: invalid frontmatter{suffix}: {error.message}")
    return errors
