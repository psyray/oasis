"""Security report project slug, run directory layout, and web indexing."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import logging

from oasis.helpers.report_project import (
    is_legacy_run_dirname,
    is_run_timestamp_dirname,
    log_input_path_project_naming_warnings,
    project_label_for_report_storage,
    project_slug_for_report_storage,
    report_date_display_from_run_key,
    run_timestamp_from_path_or_key,
    validate_project_alias_for_cli,
)
from oasis.helpers.naming import sanitize_name as shared_sanitize_name
from oasis.schemas.analysis import DashboardStats, VulnerabilityReportDocument
from oasis.tools import create_cache_dir, sanitize_name

try:
    from oasis.web import WebServer
    from oasis.report import Report
except Exception:  # pragma: no cover
    WebServer = None
    Report = None


class TestReportProjectHelpers(unittest.TestCase):
    def test_scanned_directory_basename_is_label(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "parent" / "example_app"
            p.mkdir(parents=True)
            label = project_label_for_report_storage(p)
            self.assertEqual(label, "example_app")

    def test_file_input_uses_containing_directory_name(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "parent" / "nested"
            base.mkdir(parents=True)
            f = base / "t.py"
            f.write_text("1", encoding="utf-8")
            label = project_label_for_report_storage(f)
            self.assertEqual(label, "nested")

    def test_slug_sanitizes_and_fallback(self):
        self.assertEqual(project_slug_for_report_storage("A B!"), "A_B")
        self.assertEqual(project_slug_for_report_storage("####"), "project")

    def test_validate_project_alias_for_cli(self):
        self.assertEqual(validate_project_alias_for_cli("proj_1-main"), "proj_1-main")
        with self.assertRaises(ValueError):
            validate_project_alias_for_cli("proj name!")

    def test_run_key_parsing(self):
        self.assertEqual(run_timestamp_from_path_or_key("o/p/20260110_120000"), "20260110_120000")
        self.assertEqual(run_timestamp_from_path_or_key("x_20260110_120000"), "20260110_120000")
        self.assertTrue(is_legacy_run_dirname("k_20260110_120000"))
        self.assertTrue(is_run_timestamp_dirname("20260110_120000"))
        self.assertEqual(
            report_date_display_from_run_key("k/20260110_120000"), "2026-01-10 12:00:00"
        )

    def test_log_warns_on_file_input(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "pkg" / "a.py"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("1", encoding="utf-8")
            log = logging.getLogger("test.project")
            with self.assertLogs(log, level="WARNING") as cm:
                log_input_path_project_naming_warnings(log, f)
        self.assertTrue(any("You passed a file" in m for m in cm.output))

    def test_log_warns_on_dot_input(self):
        log = logging.getLogger("test.project2")
        with self.assertLogs(log, level="WARNING") as cm:
            log_input_path_project_naming_warnings(log, Path("."))
        self.assertTrue(any("generic path" in m.lower() for m in cm.output))

    def test_create_cache_dir_uses_directory_basename(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "example" / "test_files"
            proj.mkdir(parents=True)
            cache_dir = create_cache_dir(proj)
            self.assertEqual(cache_dir.name, "test_files")

    def test_create_cache_dir_uses_alias_override(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "example" / "test_files"
            proj.mkdir(parents=True)
            cache_dir = create_cache_dir(proj, project_name="my-proj_1")
            self.assertEqual(cache_dir.name, "my_proj_1")

    def test_create_cache_dir_alias_uses_project_slug_transform(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "example" / "test_files"
            proj.mkdir(parents=True)
            alias = "A B!/team"
            cache_dir = create_cache_dir(proj, project_name=alias)
            self.assertEqual(cache_dir.name, project_slug_for_report_storage(alias))

    def test_create_cache_dir_whitespace_only_alias_falls_back_to_derived(self):
        with tempfile.TemporaryDirectory() as td:
            proj = Path(td) / "example" / "test_files"
            proj.mkdir(parents=True)
            without_alias = create_cache_dir(proj)
            with_whitespace = create_cache_dir(proj, project_name="   ")
            self.assertEqual(with_whitespace.name, without_alias.name)
            self.assertEqual(with_whitespace.name, "test_files")

    def test_shared_sanitize_name_matches_tools_contract(self):
        sample = "group/sub/Vuln Name!.md"
        self.assertEqual(shared_sanitize_name(sample), sanitize_name(sample))


@unittest.skipIf(
    WebServer is None or Report is None, "oasis.web or oasis.report not available"
)
class TestWebCollectRunLayouts(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.base = Path(self.td.name)
        # scan_root/parent/scan — security_reports is next to parent/ -> scan_root/parent/security_reports
        self.parent = self.base / "parent"
        self.scan = self.parent / "scan"
        self.scan.mkdir(parents=True)
        (self.scan / "a.py").write_text("#", encoding="utf-8")
        self.security = self.parent / "security_reports"
        self.security.mkdir()
        # Legacy flat run
        leg = self.security / "scan_20100101_120000" / "embed_m" / "json"
        leg.mkdir(parents=True)
        leg.joinpath("sqli.json").write_text(
            json.dumps(
                {
                    "schema_version": 5,
                    "report_type": "vulnerability",
                    "title": "t",
                    "generated_at": "2026-01-01 00:00:00",
                    "model_name": "m",
                    "vulnerability_name": "SQL Injection",
                    "vulnerability": {},
                    "files": [],
                    "stats": {},
                    "project": "legacyproj",
                }
            ),
            encoding="utf-8",
        )
        # Nested new layout
        nested = self.security / "example" / "20100202_120000" / "embed_m" / "json"
        nested.mkdir(parents=True)
        nested.joinpath("xss.json").write_text(
            json.dumps(
                {
                    "schema_version": 5,
                    "report_type": "vulnerability",
                    "title": "t",
                    "generated_at": "2026-01-01 00:00:00",
                    "model_name": "m",
                    "vulnerability_name": "XSS",
                    "vulnerability": {},
                    "files": [],
                    "stats": {},
                    "project": "Nested Label",
                }
            ),
            encoding="utf-8",
        )
        r = Report(str(self.scan), ["json"])
        self.server = WebServer(r)
        self.server.collect_report_data()

    def tearDown(self):
        self.td.cleanup()

    def test_collect_finds_both_runs(self):
        paths = {x["path"] for x in self.server.report_data}
        self.assertEqual(len(paths), 2)
        keys = {x["timestamp_dir"] for x in self.server.report_data}
        self.assertIn("scan_20100101_120000", keys)
        self.assertIn("example/20100202_120000", keys)
        by_leg = [x for x in self.server.report_data if "20100101" in x["timestamp_dir"]]
        by_new = [x for x in self.server.report_data if "20100202" in x["timestamp_dir"]]
        self.assertEqual(by_leg[0].get("project"), "legacyproj")
        self.assertEqual(by_new[0].get("project"), "Nested Label")

    def test_get_output_directory_nests_under_project(self):
        r = Report(str(self.scan), ["json"])
        out_base = self.parent / "out_sec"
        p = r.get_output_directory(self.scan, out_base)
        self.assertEqual(r.project, "scan")
        self.assertEqual(p.parent, out_base / (r.project_slug or ""))

    def test_get_output_directory_uses_project_name_override(self):
        r = Report(str(self.scan), ["json"])
        out_base = self.parent / "out_sec"
        p = r.get_output_directory(self.scan, out_base, project_name="alias_proj-1")
        self.assertEqual(r.project, "alias_proj-1")
        self.assertEqual(r.project_slug, "alias_proj_1")
        self.assertEqual(p.parent, out_base / "alias_proj_1")

    def test_get_output_directory_ignores_whitespace_only_project_override(self):
        r = Report(str(self.scan), ["json"])
        out_base = self.parent / "out_sec"
        p = r.get_output_directory(self.scan, out_base, project_name="   ")
        self.assertEqual(r.project, "scan")
        self.assertEqual(r.project_slug, "scan")
        self.assertEqual(p.parent, out_base / "scan")

    def test_get_output_directory_rejects_invalid_explicit_project_name(self):
        r = Report(str(self.scan), ["json"])
        out_base = self.parent / "out_sec"
        with self.assertRaises(ValueError):
            r.get_output_directory(self.scan, out_base, project_name="bad alias!")

    def test_iter_run_directories_skips_unreadable_nested_project_directory(self):
        nested_ok = self.security / "ok_project" / "20100303_120000"
        nested_ok.mkdir(parents=True)
        blocked_project = self.security / "blocked_project"
        blocked_project.mkdir(parents=True)

        original_iterdir = Path.iterdir

        def _iterdir_with_block(path_obj):
            if path_obj == blocked_project:
                raise OSError("permission denied")
            return original_iterdir(path_obj)

        with mock.patch.object(Path, "iterdir", autospec=True, side_effect=_iterdir_with_block):
            runs = list(self.server._iter_run_directories(self.security))
        run_keys = {run_key for _run_dir, run_key, _report_date in runs}
        self.assertIn("ok_project/20100303_120000", run_keys)
        self.assertNotIn("blocked_project/20100303_120000", run_keys)

    def test_project_field_from_json_path_uses_cache_for_repeated_reads(self):
        model_dir = self.security / "example" / "20100202_120000" / "embed_m"
        report_json = model_dir / "json" / "xss.json"
        self.assertTrue(report_json.is_file())
        self.server._project_field_cache.clear()

        open_calls = {"count": 0}
        original_open = open

        def _counting_open(*args, **kwargs):
            target = args[0] if args else kwargs.get("file")
            if target is not None and Path(target).resolve() == report_json.resolve():
                open_calls["count"] += 1
            return original_open(*args, **kwargs)

        with mock.patch("builtins.open", side_effect=_counting_open):
            first = self.server._project_field_from_json_path(report_json)
            second = self.server._project_field_from_json_path(report_json)
        self.assertEqual(first, "Nested Label")
        self.assertEqual(second, "Nested Label")
        self.assertEqual(open_calls["count"], 1)

    def test_project_field_cache_key_stable_when_resolve_fails(self):
        model_dir = self.security / "example" / "20100202_120000" / "embed_m"
        report_json = model_dir / "json" / "xss.json"
        self.assertTrue(report_json.is_file())
        self.server._project_field_cache.clear()

        open_calls = {"count": 0}
        original_open = open
        original_cwd = Path.cwd()

        def _counting_open(*args, **kwargs):
            target = args[0] if args else kwargs.get("file")
            if target is not None and Path(target).absolute() == report_json.absolute():
                open_calls["count"] += 1
            return original_open(*args, **kwargs)

        try:
            os.chdir(self.parent)
            relative_path = report_json.relative_to(self.parent)
            with mock.patch.object(Path, "resolve", autospec=True, side_effect=OSError("boom")):
                with mock.patch("builtins.open", side_effect=_counting_open):
                    first = self.server._project_field_from_json_path(relative_path)
                    second = self.server._project_field_from_json_path(report_json.absolute())
        finally:
            os.chdir(original_cwd)

        self.assertEqual(first, "Nested Label")
        self.assertEqual(second, "Nested Label")
        self.assertEqual(open_calls["count"], 1)


class TestVulnerabilityJsonProjectField(unittest.TestCase):
    def test_roundtrip_project_optional(self):
        doc = VulnerabilityReportDocument(
            title="SQL Injection Security Analysis",
            generated_at="2026-01-01 12:00:00",
            model_name="test-model",
            vulnerability_name="SQL Injection",
            vulnerability={"name": "SQL Injection"},
            files=[],
            stats=DashboardStats(),
            project="myproj",
        )
        raw = doc.model_dump_json()
        d2 = VulnerabilityReportDocument.model_validate_json(raw)
        self.assertEqual(d2.project, "myproj")


@unittest.skipIf(Report is None, "oasis.report not available")
class TestReportProjectInitialization(unittest.TestCase):
    def test_report_initializes_project_and_slug_from_input_path(self):
        with tempfile.TemporaryDirectory() as td:
            scan_dir = Path(td) / "project_alpha"
            scan_dir.mkdir(parents=True)
            report = Report(str(scan_dir), ["json"])
            self.assertEqual(report.project, "project_alpha")
            self.assertTrue(bool(report.project_slug))
