from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, mock

from support import load_module

check = load_module("check")


class CheckTests(TestCase):
    def test_selected_checks_defaults_to_all_checks(self) -> None:
        selected = check.selected_checks([], False, Path("."))

        self.assertEqual([entry.name for entry in selected], ["catalog", "guides", "standards", "labels"])

    def test_selected_checks_filters_to_changed_paths(self) -> None:
        with (
            TemporaryDirectory() as tmpdir,
            mock.patch.object(check, "changed_paths", return_value={"catalog/standards/owasp-2025.json"}),
        ):
            selected = check.selected_checks([], True, Path(tmpdir))

        self.assertEqual([entry.name for entry in selected], ["standards"])

    def test_selected_checks_runs_requested_check_when_no_paths_match(self) -> None:
        with TemporaryDirectory() as tmpdir, mock.patch.object(check, "changed_paths", return_value={"README.md"}):
            selected = check.selected_checks(["catalog"], True, Path(tmpdir))

        self.assertEqual([entry.name for entry in selected], ["catalog"])

    def test_main_reports_all_failed_checks(self) -> None:
        stdout = StringIO()
        stderr = StringIO()
        with (
            mock.patch.object(check, "run_check", side_effect=[False, True, False]),
            mock.patch.object(check, "ROOT", Path(".")),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = check.main(["--check", "catalog", "--check", "guides", "--check", "standards"])

        self.assertEqual(code, 1)
        self.assertIn("Repository checks failed: catalog, standards.", stderr.getvalue())
