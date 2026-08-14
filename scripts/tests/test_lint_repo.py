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
                severity: high
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
                severity: high
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
                severity: high
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
                severity: high
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
                severity: high
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
