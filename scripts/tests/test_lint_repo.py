from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from support import build_valid_repo, load_module, run_main, write

lint_repo = load_module("lint_repo")


class LintRepoTests(TestCase):
    def test_valid_repo_passes_and_ignores_urls_inside_code_fences(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)

            code, stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Linting guide metadata and allowlisted rendered URLs.", stdout)
            self.assertIn("Repository lint passed.", stdout)

    def test_valid_repo_passes_and_ignores_urls_inside_tilde_fences(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/sensitive-data-exposure/hard-coded-secrets.md",
                """
                ---
                id: WOF-SDE-001
                title: Hard-coded Secrets
                kind: vulnerability
                default_severity: high
                exploitability: medium
                standards:
                  cwe:
                    - CWE-798
                  owasp_top_10:
                    - "A07:2025 Authentication Failures"
                platforms:
                  - server
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - secret
                tags:
                  - secrets
                ---

                ## Example Attack

                ~~~text
                HTTPS://bad.example/should-not-be-linted
                ~~~

                ## References

                - [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
                - [OWASP Top 10 2025 A07: Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
                """,
            )

            code, stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 0)
            self.assertEqual(stderr, "")
            self.assertIn("Repository lint passed.", stdout)

    def test_disallowed_reference_domain_fails(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/sensitive-data-exposure/hard-coded-secrets.md",
                """
                ---
                id: WOF-SDE-001
                title: Hard-coded Secrets
                kind: vulnerability
                default_severity: high
                exploitability: medium
                standards:
                  cwe:
                    - CWE-798
                  owasp_top_10:
                    - "A07:2025 Authentication Failures"
                platforms:
                  - server
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - secret
                tags:
                  - secrets
                ---

                ## References

                - [Bad Ref](https://bad.example/docs)
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn("bad.example", stderr)
            self.assertIn("guide-references", stderr)

    def test_invalid_allowed_domains_config_is_reported(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "catalog/allowed-reference-domains.json",
                """
                {
                  "schema_version": 2,
                  "domains": [
                    {
                      "scopes": ["guide-references"],
                      "purpose": "Missing domain"
                    },
                    {
                      "domain": "Bad.Example",
                      "scopes": ["guide-references"],
                      "purpose": ""
                    }
                  ]
                }
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn("catalog/allowed-reference-domains.json: schema_version must equal 1", stderr)
            self.assertIn(
                "catalog/allowed-reference-domains.json: domains[0].domain must be a non-empty string",
                stderr,
            )
            self.assertIn(
                "catalog/allowed-reference-domains.json: domains[1].domain must be a non-empty lowercase hostname",
                stderr,
            )
            self.assertIn(
                "catalog/allowed-reference-domains.json: domains[1].purpose must be a non-empty string",
                stderr,
            )

    def test_empty_allowed_domains_list_is_reported(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "catalog/allowed-reference-domains.json",
                """
                {
                  "schema_version": 1,
                  "domains": []
                }
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn("catalog/allowed-reference-domains.json: domains must be a non-empty list", stderr)

    def test_non_integer_schema_version_is_reported(self) -> None:
        for schema_version in ("true", "1.0"):
            with self.subTest(schema_version=schema_version), TemporaryDirectory() as tmpdir:
                root = Path(tmpdir)
                build_valid_repo(root)
                write(
                    root / "catalog/allowed-reference-domains.json",
                    f"""
                        {{
                          "schema_version": {schema_version},
                          "domains": [
                            {{
                              "domain": "cwe.mitre.org",
                              "scopes": ["guide-references"],
                              "purpose": "CWE references"
                            }}
                          ]
                        }}
                        """,
                )

                code, _stdout, stderr = run_main(lint_repo, root)

                self.assertEqual(code, 1)
                self.assertIn(
                    "catalog/allowed-reference-domains.json: schema_version must equal 1",
                    stderr,
                )

    def test_unknown_allowed_domain_scope_is_reported(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "catalog/allowed-reference-domains.json",
                """
                {
                  "schema_version": 1,
                  "domains": [
                    {
                      "domain": "cwe.mitre.org",
                      "scopes": ["not-a-scope"],
                      "purpose": "CWE references"
                    }
                  ]
                }
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn(
                "catalog/allowed-reference-domains.json: domains[0].scopes[0] must be one of: "
                "example-urls, guide-references",
                stderr,
            )

    def test_duplicate_allowed_domain_scope_is_reported(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "catalog/allowed-reference-domains.json",
                """
                {
                  "schema_version": 1,
                  "domains": [
                    {
                      "domain": "example.com",
                      "scopes": ["example-urls"],
                      "purpose": "Example URLs"
                    },
                    {
                      "domain": "example.com",
                      "scopes": ["example-urls"],
                      "purpose": "Duplicate entry"
                    }
                  ]
                }
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn(
                "catalog/allowed-reference-domains.json: duplicate domain/scope combination for "
                "'example.com' and 'example-urls'",
                stderr,
            )

    def test_uppercase_https_reference_domain_is_checked(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/sensitive-data-exposure/hard-coded-secrets.md",
                """
                ---
                id: WOF-SDE-001
                title: Hard-coded Secrets
                kind: vulnerability
                default_severity: high
                exploitability: medium
                standards:
                  cwe:
                    - CWE-798
                  owasp_top_10:
                    - "A07:2025 Authentication Failures"
                platforms:
                  - server
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - secret
                tags:
                  - secrets
                ---

                ## References

                - [Bad Ref](HTTPS://bad.example/docs)
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn("bad.example", stderr)
            self.assertIn("guide-references", stderr)

    def test_protocol_relative_reference_domain_is_checked(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/sensitive-data-exposure/hard-coded-secrets.md",
                """
                ---
                id: WOF-SDE-001
                title: Hard-coded Secrets
                kind: vulnerability
                default_severity: high
                exploitability: medium
                standards:
                  cwe:
                    - CWE-798
                  owasp_top_10:
                    - "A07:2025 Authentication Failures"
                platforms:
                  - server
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - secret
                tags:
                  - secrets
                ---

                ## References

                - [Bad Ref](//bad.example/docs)
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn("bad.example", stderr)
            self.assertIn("guide-references", stderr)

    def test_frontmatter_errors_are_reported(self) -> None:
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
                tags:
                  - xss
                ---

                ## References

                - [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn("dataflow guides must declare non-empty sources", stderr)
            self.assertIn("dataflow guides must declare non-empty sinks", stderr)

    def test_standard_reference_mismatch_is_reported(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/sensitive-data-exposure/hard-coded-secrets.md",
                """
                ---
                id: WOF-SDE-001
                title: Hard-coded Secrets
                kind: vulnerability
                default_severity: high
                exploitability: medium
                standards:
                  cwe:
                    - CWE-798
                  owasp_top_10:
                    - "A07:2025 Authentication Failures"
                platforms:
                  - server
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - secret
                tags:
                  - secrets
                ---

                ## References

                - [CWE-352](https://cwe.mitre.org/data/definitions/352.html)
                - [OWASP Top 10 2025 A01: Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn(
                "standards.cwe entry 'CWE-798' must have matching reference "
                "https://cwe.mitre.org/data/definitions/798.html",
                stderr,
            )
            self.assertIn(
                "standards.owasp_top_10 entry 'A07:2025 Authentication Failures' must have "
                "matching reference "
                "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
                stderr,
            )

    def test_missing_nearest_readme_link_fails(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/injection/xss/README.md",
                """
                # Cross-site scripting (XSS)

                ## Rules
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn(
                "nearest index guides/injection/xss/README.md must link to this guide exactly once (found 0)",
                stderr,
            )

    def test_duplicate_nearest_readme_link_fails(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/injection/xss/README.md",
                """
                # Cross-site scripting (XSS)

                ## Rules

                - [Rule A](url-derived-input-to-html-sink-innerhtml.md)
                - [Rule B](url-derived-input-to-html-sink-innerhtml.md)
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn(
                "nearest index guides/injection/xss/README.md must link to this guide exactly once (found 2)",
                stderr,
            )

    def test_broken_index_readme_link_fails(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/injection/README.md",
                """
                # Injection

                ## Categories

                - [Cross-site scripting (XSS)](missing/README.md)
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn("linked markdown target does not exist: missing/README.md", stderr)

    def test_commented_out_index_link_does_not_count(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/injection/xss/README.md",
                """
                # Cross-site scripting (XSS)

                ## Rules

                <!-- - [Rule](url-derived-input-to-html-sink-innerhtml.md) -->
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn(
                "nearest index guides/injection/xss/README.md must link to this guide exactly once (found 0)",
                stderr,
            )

    def test_reference_style_index_links_are_rejected(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            write(
                root / "guides/injection/xss/README.md",
                """
                # Cross-site scripting (XSS)

                ## Rules

                - [Rule][xss-rule]

                [xss-rule]: url-derived-input-to-html-sink-innerhtml.md
                """,
            )

            code, _stdout, stderr = run_main(lint_repo, root)

            self.assertEqual(code, 1)
            self.assertIn("category indexes must use inline Markdown links, not reference-style links", stderr)
