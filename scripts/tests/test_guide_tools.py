from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent
from unittest import TestCase

from support import load_module, write

guide_tools = load_module("guide_tools")


class GuideToolsTests(TestCase):
    def test_iter_guide_rule_paths_excludes_note_files(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            write(root / "guides/injection/xss/README.md", "# XSS\n")
            write(
                root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md",
                "# Real guide\n",
            )
            write(root / "guides/injection/xss/notes/self-xss.md", "# Note\n")

            paths = guide_tools.iter_guide_rule_paths(root)

            self.assertEqual(
                paths,
                [root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md"],
            )

    def test_parse_yaml_supports_standard_yaml_features(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                title: >
                  A title with a colon:
                  and a folded line
                tags: [xss, dom-xss]
                defaults: &defaults
                  severity: high
                copied_defaults: *defaults
                """
            ).lstrip(),
            Path("guide.md"),
        )

        self.assertEqual(frontmatter["title"], "A title with a colon: and a folded line\n")
        self.assertEqual(frontmatter["tags"], ["xss", "dom-xss"])
        self.assertEqual(frontmatter["copied_defaults"], {"severity": "high"})

    def test_parse_yaml_rejects_invalid_yaml(self) -> None:
        with self.assertRaises(guide_tools.GuideValidationError) as error:
            guide_tools.parse_yaml_mapping("title: Foo: Bar", Path("guide.md"))

        self.assertIn("invalid YAML frontmatter", str(error.exception))

    def test_parse_yaml_rejects_duplicate_keys(self) -> None:
        with self.assertRaises(guide_tools.GuideValidationError) as error:
            guide_tools.parse_yaml_mapping("title: First\ntitle: Second", Path("guide.md"))

        self.assertIn("duplicate key 'title'", str(error.exception))

    def test_validate_frontmatter_accepts_structured_owasp_relationship(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-XSS-001
                title: DOM XSS
                kind: vulnerability
                default_severity: high
                exploitability: high
                standards:
                  cwe:
                    - CWE-79
                  owasp_top_10:
                    - id: "A05:2025 Injection"
                      relationship: direct
                  mappings:
                    - cwe: CWE-79
                      owasp_top_10: "A05:2025 Injection"
                      relationship: direct
                platforms:
                  - browser
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - innerHTML
                tags:
                  - xss
                """
            ).lstrip(),
            Path("guide.md"),
        )

        self.assertEqual(guide_tools.validate_frontmatter(frontmatter, Path("guide.md")), [])

    def test_validate_frontmatter_rejects_undeclared_standard_mapping(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-XSS-001
                title: DOM XSS
                kind: vulnerability
                default_severity: high
                exploitability: high
                standards:
                  cwe:
                    - CWE-79
                  owasp_top_10:
                    - id: "A05:2025 Injection"
                      relationship: direct
                  mappings:
                    - cwe: CWE-89
                      owasp_top_10: "A05:2025 Injection"
                      relationship: direct
                platforms:
                  - browser
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - innerHTML
                tags:
                  - xss
                """
            ).lstrip(),
            Path("guide.md"),
        )

        errors = guide_tools.validate_frontmatter(frontmatter, Path("guide.md"))

        self.assertIn(
            "guide.md: standards.mappings[0].cwe must be declared in standards.cwe",
            errors,
        )

    def test_validate_frontmatter_rejects_empty_required_strings_and_entries(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id:
                title: ""
                kind:
                  nested: value
                default_severity: high
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

        for field in (
            "id",
            "title",
            "kind",
            "exploitability",
            "languages",
            "methods",
            "candidate_tokens",
            "indicators",
        ):
            with self.subTest(field=field):
                self.assertTrue(any(f"{field}" in error for error in errors))

    def test_validate_frontmatter_rejects_empty_sources_and_sinks_entries(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-XSS-001
                title: URL-derived Input to HTML Sink
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

        self.assertTrue(any("sources.0" in error for error in errors))
        self.assertTrue(any("sinks.0" in error for error in errors))

    def test_validate_frontmatter_rejects_dataflow_guides_with_indicators(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-XSS-001
                title: URL-derived Input to HTML Sink
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
                  - javascript
                detection:
                  type: dataflow
                  methods:
                    - grep
                sources:
                  - window.location.search
                sinks:
                  - Element.innerHTML
                indicators:
                  - innerHTML
                tags:
                  - xss
                """
            ).lstrip(),
            Path("guide.md"),
        )

        errors = guide_tools.validate_frontmatter(frontmatter, Path("guide.md"))

        self.assertTrue(any("innerHTML" in error for error in errors))

    def test_validate_frontmatter_rejects_semantic_pattern_guides_with_sources_and_sinks(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-PM-001
                title: Untrusted postMessage Sender to Privileged Handler
                kind: vulnerability
                default_severity: high
                exploitability: medium
                standards:
                  cwe:
                    - CWE-940
                  owasp_top_10:
                    - "A07:2025 Authentication Failures"
                platforms:
                  - browser
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - addEventListener("message"
                sources:
                  - MessageEvent.data
                sinks:
                  - fetch()
                tags:
                  - postmessage
                """
            ).lstrip(),
            Path("guide.md"),
        )

        errors = guide_tools.validate_frontmatter(frontmatter, Path("guide.md"))

        self.assertTrue(any("MessageEvent.data" in error for error in errors))
        self.assertTrue(any("fetch()" in error for error in errors))

    def test_validate_frontmatter_rejects_unexpected_detection_keys(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-XSS-001
                title: URL-derived Input to HTML Sink
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

        self.assertTrue(any("query" in error for error in errors))

    def test_validate_frontmatter_rejects_invalid_standards_keys_and_values(self) -> None:
        frontmatter = guide_tools.parse_yaml_mapping(
            dedent(
                """
                id: WOF-XSS-001
                title: URL-derived Input to HTML Sink
                kind: vulnerability
                default_severity: high
                exploitability: high
                standards:
                  cwe:
                    - banana
                  owasp_top_10:
                    - banana
                  whatever:
                    - hello
                platforms:
                  - browser
                languages:
                  - javascript
                detection:
                  type: semantic-pattern
                  methods:
                    - grep
                indicators:
                  - innerHTML
                tags:
                  - xss
                """
            ).lstrip(),
            Path("guide.md"),
        )

        errors = guide_tools.validate_frontmatter(frontmatter, Path("guide.md"))

        self.assertTrue(any("whatever" in error for error in errors))
        self.assertTrue(any("standards.cwe.0" in error for error in errors))
        self.assertTrue(any("standards.owasp_top_10.0" in error for error in errors))

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

    def test_is_guide_note_path_detects_notes_directory(self) -> None:
        guides_root = Path("/repo/guides")

        self.assertTrue(
            guide_tools.is_guide_note_path(
                guides_root / "injection" / "xss" / "notes" / "self-xss.md",
                guides_root,
            )
        )
        self.assertFalse(
            guide_tools.is_guide_note_path(
                guides_root / "injection" / "xss" / "url-derived-input-to-html-sink-innerhtml.md",
                guides_root,
            )
        )
