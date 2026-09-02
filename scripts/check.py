from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Check:
    name: str
    script: str
    arguments: tuple[str, ...]
    relevant_prefixes: tuple[str, ...]


CHECKS = (
    Check(
        "catalog",
        "scripts/generate_catalog.py",
        ("--check",),
        ("catalog/rules.json", "guides/", "scripts/generate_catalog.py", "scripts/guide_tools.py"),
    ),
    Check(
        "guides",
        "scripts/lint_repo.py",
        (),
        (
            "catalog/allowed-reference-domains.json",
            "guides/",
            "scripts/generate_catalog.py",
            "scripts/guide_tools.py",
            "scripts/lint_repo.py",
        ),
    ),
    Check(
        "standards",
        "scripts/validate_standards.py",
        (),
        ("catalog/standards/", "guides/", "scripts/guide_tools.py", "scripts/validate_standards.py"),
    ),
    Check(
        "labels",
        "scripts/sync_guide_labels.py",
        ("--check",),
        (".github/labeler.yaml", ".github/labels.yaml", "guides/", "scripts/sync_guide_labels.py"),
    ),
)
CHECK_BY_NAME = {check.name: check for check in CHECKS}


def changed_paths(root: Path) -> set[str]:
    """Return tracked and untracked working-tree paths for local changed-only runs."""
    try:
        tracked = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        return set()
    return set(tracked) | set(untracked)


def is_relevant(check: Check, paths: Iterable[str]) -> bool:
    return any(path == prefix or path.startswith(prefix) for path in paths for prefix in check.relevant_prefixes)


def selected_checks(names: list[str], changed_only: bool, root: Path) -> tuple[Check, ...]:
    selected = tuple(CHECK_BY_NAME[name] for name in names) if names else CHECKS
    if not changed_only:
        return selected

    paths = changed_paths(root)
    # A clean tree or unavailable Git metadata should never silently skip validation.
    return tuple(check for check in selected if is_relevant(check, paths)) or selected


def run_check(check: Check, root: Path) -> bool:
    print(f"==> Running {check.name} check", flush=True)
    command = [sys.executable, str(root / check.script), *check.arguments]
    return subprocess.run(command, cwd=root, check=False).returncode == 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Web of Flaws repository integrity checks.")
    parser.add_argument("--check", choices=CHECK_BY_NAME, action="append", dest="checks", help="Run one named check.")
    parser.add_argument(
        "--changed-only",
        action="store_true",
        help="Run only checks relevant to modified or untracked working-tree files.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    checks = selected_checks(args.checks or [], args.changed_only, ROOT)
    failures = [check.name for check in checks if not run_check(check, ROOT)]
    if failures:
        print(f"Repository checks failed: {', '.join(failures)}.", file=sys.stderr)
        return 1
    print(f"Repository checks passed: {', '.join(check.name for check in checks)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
