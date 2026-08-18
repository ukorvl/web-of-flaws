from __future__ import annotations

from pathlib import Path
from textwrap import dedent
from unittest import TestCase

from support import load_module


guide_tools = load_module("guide_tools")


class GuideToolsTests(TestCase):
    def test_parse_yaml_rejects_unquoted_parser_sensitive_scalars(self) -> None:
        with self.assertRaises(guide_tools.GuideValidationError) as error:
            guide_tools.parse_yaml_mapping("title: Foo: Bar", Path("guide.md"))

        self.assertIn("unsupported plain YAML scalar", str(error.exception))

    def test_parse_yaml_rejects_unterminated_quoted_scalars(self) -> None:
        with self.assertRaises(guide_tools.GuideValidationError) as error:
            guide_tools.parse_yaml_mapping('title: "unterminated', Path("guide.md"))

        self.assertIn("unsupported quoted YAML scalar", str(error.exception))

    def test_parse_yaml_rejects_indicator_prefixed_scalars(self) -> None:
        for value in ("[Foo]", "*alias", "&anchor Foo", "| block", "> folded"):
            with self.subTest(value=value):
                with self.assertRaises(guide_tools.GuideValidationError) as error:
                    guide_tools.parse_yaml_mapping(f"title: {value}", Path("guide.md"))

                self.assertIn("unsupported plain YAML scalar", str(error.exception))

    def test_validate_frontmatter_rejects_empty_required_strings_and_entries(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id:
                title: ""
                kind:
                  nested: value
                severity: high
                exploitability:
                standards:
                  cwe:
                    - CWE-79
                  owasp_top_10:
                    - "A05:2025 Injection"
                platforms:
                  - browser
                languages:
                  - ""
                detection:
                  type: semantic-pattern
                  methods:
                    - ""
                  candidate_tokens:
                    - ""
                indicators:
                  - ""
                tags:
                  - xss
                """
            ).lstrip(),
            Path("guide.md"),
        )

        errors = guide_tools.validate_frontmatter(frontmatter, Path("guide.md"))

        self.assertIn("guide.md: id must be a non-empty string", errors)
        self.assertIn("guide.md: title must be a non-empty string", errors)
        self.assertIn("guide.md: kind must be a non-empty string", errors)
        self.assertIn("guide.md: exploitability must be a non-empty string", errors)
        self.assertIn("guide.md: languages entries must be non-empty strings", errors)
        self.assertIn("guide.md: detection.methods entries must be non-empty strings", errors)
        self.assertIn("guide.md: detection.candidate_tokens entries must be non-empty strings", errors)
        self.assertIn("guide.md: indicators entries must be non-empty strings", errors)

    def test_validate_frontmatter_rejects_empty_sources_and_sinks_entries(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-XSS-001
                title: URL-derived Input to HTML Sink
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
                  - javascript
                detection:
                  type: dataflow
                  methods:
                    - grep
                sources:
                  - ""
                sinks:
                  - ""
                tags:
                  - xss
                """
            ).lstrip(),
            Path("guide.md"),
        )

        errors = guide_tools.validate_frontmatter(frontmatter, Path("guide.md"))

        self.assertIn("guide.md: sources entries must be non-empty strings", errors)
        self.assertIn("guide.md: sinks entries must be non-empty strings", errors)

    def test_validate_frontmatter_rejects_unexpected_detection_keys(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-XSS-001
                title: URL-derived Input to HTML Sink
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
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                  candidate_tokens:
                    - innerHTML
                  query:
                    grep:
                      - innerHTML
                indicators:
                  - innerHTML
                tags:
                  - xss
                """
            ).lstrip(),
            Path("guide.md"),
        )

        errors = guide_tools.validate_frontmatter(frontmatter, Path("guide.md"))

        self.assertIn("guide.md: unexpected detection keys: query", errors)

    def test_rendered_urls_matches_uppercase_schemes_and_ignores_tilde_fences(self) -> None:
        markdown = """
        [Reference](HTTPS://docs.example.com/guide)
        [Network Path](//docs.example.com/network-path)

        ~~~js
        const attack = "HTTPS://evil.example/payload";
        ~~~
        """

        self.assertEqual(
            guide_tools.rendered_urls(markdown),
            [
                ("HTTPS://docs.example.com/guide", 2),
                ("//docs.example.com/network-path", 3),
            ],
        )

    def test_rendered_urls_ignores_multi_backtick_inline_code_spans(self) -> None:
        markdown = """
        Inline code ``https://ignored.example/with`backtick`` should not be linted.
        [Reference](https://docs.example.com/guide)
        """

        self.assertEqual(
            guide_tools.rendered_urls(markdown),
            [("https://docs.example.com/guide", 3)],
        )
