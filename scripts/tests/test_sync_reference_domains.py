from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from support import build_valid_repo, load_module, run_main

sync_reference_domains = load_module("sync_reference_domains")


class SyncReferenceDomainsTests(TestCase):
    def test_collect_domain_scopes_uses_rendered_url_sections(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            guide = root / "guides/sensitive-data-exposure/hard-coded-secrets.md"
            guide.write_text(
                guide.read_text(encoding="utf-8")
                .replace(
                    "## References",
                    "See https://example.com/demo.\n\n## References",
                )
                .replace(
                    "## Quick Checklist",
                    "- [Additional documentation](https://docs.example.org/reference)\n\n## Quick Checklist",
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                sync_reference_domains.collect_domain_scopes(root),
                {
                    "cwe.mitre.org": {"guide-references"},
                    "docs.example.org": {"guide-references"},
                    "example.com": {"example-urls"},
                    "owasp.org": {"guide-references"},
                },
            )

    def test_main_syncs_domains_preserves_purposes_and_check_then_passes(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            guide = root / "guides/sensitive-data-exposure/hard-coded-secrets.md"
            guide.write_text(
                guide.read_text(encoding="utf-8").replace(
                    "## Quick Checklist",
                    "- [Additional documentation](https://docs.example.org/reference)\n\n## Quick Checklist",
                ),
                encoding="utf-8",
            )

            code, stdout, stderr = run_main(sync_reference_domains, root)

            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Syncing reference domain allowlist for 3 domains.", stdout)
            self.assertIn("Updated catalog/allowed-reference-domains.json.", stdout)
            payload = json.loads((root / "catalog/allowed-reference-domains.json").read_text(encoding="utf-8"))
            self.assertEqual(
                payload["domains"],
                [
                    {
                        "domain": "cwe.mitre.org",
                        "scopes": ["guide-references"],
                        "purpose": "CWE references",
                    },
                    {
                        "domain": "docs.example.org",
                        "scopes": ["guide-references"],
                        "purpose": ("Documentation hosted at docs.example.org and referenced by repository guides."),
                    },
                    {
                        "domain": "owasp.org",
                        "scopes": ["guide-references"],
                        "purpose": "OWASP references",
                    },
                ],
            )

            check_code, check_stdout, check_stderr = run_main(sync_reference_domains, root, "--check")

            self.assertEqual(check_code, 0)
            self.assertEqual(check_stderr, "")
            self.assertIn("Checking reference domain allowlist for 3 domains.", check_stdout)
            self.assertIn("catalog/allowed-reference-domains.json is up to date.", check_stdout)

    def test_main_check_reports_outdated_allowlist(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)

            code, stdout, stderr = run_main(sync_reference_domains, root, "--check")

            self.assertEqual(code, 1)
            self.assertIn("Checking reference domain allowlist for 2 domains.", stdout)
            self.assertIn("catalog/allowed-reference-domains.json is out of date.", stderr)
            self.assertIn("Run: python3 scripts/sync_reference_domains.py", stderr)
