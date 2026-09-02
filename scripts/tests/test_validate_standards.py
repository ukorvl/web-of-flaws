from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from support import build_valid_repo, load_module, write

validate_standards = load_module("validate_standards")


class ValidateStandardsTests(TestCase):
    def test_validate_accepts_declared_direct_relationships(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)

            self.assertEqual(validate_standards.validate(root), [])

    def test_validate_rejects_undeclared_cwe(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            guide = root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md"
            guide.write_text(guide.read_text(encoding="utf-8").replace("CWE-79", "CWE-999"), encoding="utf-8")

            errors = validate_standards.validate(root)

            self.assertEqual(len(errors), 1)
            self.assertIn("standards.cwe entry 'CWE-999' is not declared", errors[0])

    def test_validate_rejects_undeclared_owasp_entry(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            guide = root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md"
            guide.write_text(
                guide.read_text(encoding="utf-8").replace("A05:2025 Injection", "A10:2025 Mishandled Exceptions"),
                encoding="utf-8",
            )

            errors = validate_standards.validate(root)

            self.assertEqual(len(errors), 1)
            self.assertIn("standards.owasp_top_10 entry 'A10:2025 Mishandled Exceptions' is not declared", errors[0])

    def test_validate_rejects_undeclared_direct_relationship(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            build_valid_repo(root)
            guide = root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md"
            guide.write_text(
                guide.read_text(encoding="utf-8").replace("A05:2025 Injection", "A07:2025 Authentication Failures"),
                encoding="utf-8",
            )

            errors = validate_standards.validate(root)

            self.assertEqual(len(errors), 1)
            self.assertIn("direct CWE/OWASP relationship 'CWE-79' -> 'A07:2025 Authentication Failures'", errors[0])

    def test_load_owasp_2025_rejects_invalid_dataset(self) -> None:
        with TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            standards_path = root / "catalog/standards/owasp-2025.json"
            write(standards_path, '{"A05:2025 Injection": {"cwes": ["not-a-cwe"]}}')

            with self.assertRaises(validate_standards.StandardsValidationError) as error:
                validate_standards.load_owasp_2025(root)

            self.assertIn("contains invalid CWE values", str(error.exception))
