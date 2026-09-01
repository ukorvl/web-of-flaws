from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from support import build_valid_repo, load_module, run_main, write

generate_catalog = load_module("generate_catalog")
guide_tools = load_module("guide_tools")


class GenerateCatalogTests(TestCase):
    maxDiff = None

    def test_build_rules_reads_frontmatter_and_references_from_guides(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)

            rules = generate_catalog.build_rules(root)

            self.assertEqual(
                [rule["path"] for rule in rules],
                [
                    "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md",
                    "guides/sensitive-data-exposure/hard-coded-secrets.md",
                ],
            )
            self.assertEqual(len(rules[0]["references"]), 2)
            self.assertEqual(rules[0]["references"][0]["label"], "CWE-79")
            self.assertEqual(rules[0]["detection"]["candidate_tokens"], ["innerHTML", "URLSearchParams"])
            self.assertEqual(rules[1]["detection"]["candidate_tokens"], ["SECRET", "BEGIN PRIVATE KEY"])

    def test_build_rules_rejects_duplicate_rule_ids(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/sensitive-data-exposure/duplicate.md",
                """
                ---
                id: WOF-XSS-001
                title: Duplicate
                kind: vulnerability
                default_severity: low
                exploitability: low
                standards:
                  cwe:
                    - CWE-1
                  owasp_top_10:
                    - "A01:2025 Broken Access Control"
                platforms:
                  - server
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - duplicate
                tags:
                  - duplicate
                ---

                ## References

                - [CWE-1](https://cwe.mitre.org/data/definitions/1.html)
                """,
            )

            with self.assertRaises(guide_tools.GuideValidationError) as error:
                generate_catalog.build_rules(root)

            self.assertIn("duplicate rule id 'WOF-XSS-001'", str(error.exception))

    def test_build_rules_ignores_note_files(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/injection/xss/notes/self-xss.md",
                """
                # Self-XSS

                Informational note without guide frontmatter.
                """,
            )

            rules = generate_catalog.build_rules(root)

            self.assertEqual(len(rules), 2)
            self.assertEqual(
                [rule["path"] for rule in rules],
                [
                    "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md",
                    "guides/sensitive-data-exposure/hard-coded-secrets.md",
                ],
            )

    def test_build_rules_requires_matching_standard_references(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md",
                """
                ---
                id: WOF-XSS-001
                title: URL-derived Input to HTML Sink (innerHTML)
                kind: vulnerability
                default_severity: high
                exploitability: high
                standards:
                  cwe:
                    - CWE-79
                  owasp_top_10:
                    - "A05:2025 Injection"
                platforms:
                  - browser
                languages:
                  - html
                detection:
                  type: dataflow
                  methods:
                    - grep
                sources:
                  - window.location.search
                sinks:
                  - Element.innerHTML
                tags:
                  - xss
                ---

                ## References

                - [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
                - [OWASP Top 10 2025 A01: Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
                """,
            )

            with self.assertRaises(guide_tools.GuideValidationError) as error:
                generate_catalog.build_rules(root)

            self.assertIn(
                "standards.cwe entry 'CWE-79' must have matching reference "
                "https://cwe.mitre.org/data/definitions/79.html",
                str(error.exception),
            )
            self.assertIn(
                "standards.owasp_top_10 entry 'A05:2025 Injection' must have matching reference "
                "https://owasp.org/Top10/2025/A05_2025-Injection/",
                str(error.exception),
            )

    def test_build_rules_rejects_invalid_standards_metadata(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md",
                """
                ---
                id: WOF-XSS-001
                title: URL-derived Input to HTML Sink (innerHTML)
                kind: vulnerability
                default_severity: high
                exploitability: high
                standards:
                  cwe:
                    - CWE-79
                  owasp_top_10:
                    - banana
                  whatever:
                    - hello
                platforms:
                  - browser
                languages:
                  - html
                detection:
                  type: dataflow
                  methods:
                    - grep
                sources:
                  - window.location.search
                sinks:
                  - Element.innerHTML
                tags:
                  - xss
                ---

                ## References

                - [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
                - [OWASP Top 10 2025 A05: Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
                """,
            )

            with self.assertRaises(guide_tools.GuideValidationError) as error:
                generate_catalog.build_rules(root)

            self.assertIn("unexpected standards keys: whatever", str(error.exception))
            self.assertIn("OWASP Top 10 value 'banana' must match ^[AX]\\d{2}:\\d{4} .+$", str(error.exception))

    def test_expected_owasp_top_10_reference_supports_x_series_next_steps(self) -> None:
        self.assertEqual(
            generate_catalog.expected_owasp_top_10_reference("X01:2025 Lack of Application Resilience"),
            "https://owasp.org/Top10/2025/X01_2025-Next_Steps/",
        )

    def test_main_sync_and_check_modes(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            (root / "catalog").mkdir(exist_ok=True)

            code, stdout, stderr = run_main(generate_catalog, root)
            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Generating catalog/rules.json for 2 rules.", stdout)
            self.assertIn("Updated catalog/rules.json.", stdout)

            check_code, check_stdout, check_stderr = run_main(generate_catalog, root, "--check")
            self.assertEqual(check_code, 0)
            self.assertEqual(check_stderr, "")
            self.assertIn("Checking catalog/rules.json for 2 rules.", check_stdout)
            self.assertIn("catalog/rules.json is up to date.", check_stdout)

    def test_main_check_reports_outdated_catalog(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(root / "catalog/rules.json", '{"schema_version":1,"rules":[]}\n')

            code, stdout, stderr = run_main(generate_catalog, root, "--check")
            self.assertEqual(code, 1)
            self.assertIn("Checking catalog/rules.json for 2 rules.", stdout)
            self.assertIn("catalog/rules.json is out of date.", stderr)

    def test_main_reports_invalid_guides_without_traceback(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            (root / "catalog").mkdir(exist_ok=True)
            write(
                root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md",
                """
                ---
                id:
                title: URL-derived Input to HTML Sink (innerHTML)
                kind: vulnerability
                default_severity: high
                exploitability: high
                standards:
                  cwe:
                    - CWE-79
                  owasp_top_10:
                    - "A05:2025 Injection"
                platforms:
                  - browser
                languages:
                  - html
                detection:
                  type: dataflow
                  methods:
                    - grep
                sources:
                  - window.location.search
                sinks:
                  - Element.innerHTML
                tags:
                  - xss
                ---

                ## References

                - [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
                """,
            )

            code, stdout, stderr = run_main(generate_catalog, root, "--check")

            self.assertEqual(code, 1)
            self.assertEqual(stdout, "")
            self.assertIn("id must be a non-empty string", stderr)
            self.assertIn("Catalog generation failed due to invalid guide metadata.", stderr)
