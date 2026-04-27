"""Tests for pure dashboard helper functions."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.dashboard import (
    dashboard_format_display_order,
    dashboard_reports_href,
    expand_socketio_cors_config_entries,
    preferred_detail_relative_path_and_format,
    rewrite_report_preview_anchor_hrefs,
)
from oasis.helpers.dashboard.json_sibling import json_sibling_for_format_artifact


class TestHelpersDashboard(unittest.TestCase):
    def test_dashboard_format_display_order_preserves_canonical_casing(self):
        order = dashboard_format_display_order()
        self.assertTrue(order)
        lower_seen = set()
        for fmt in order:
            key = fmt.lower()
            self.assertNotIn(key, lower_seen)
            lower_seen.add(key)

    def test_expand_socketio_cors_substitutes_port_placeholder(self):
        expanded = expand_socketio_cors_config_entries(
            ["http://127.0.0.1:{port}", "https://example.invalid:{port}"],
            port=5050,
        )
        self.assertEqual(
            expanded,
            ["http://127.0.0.1:5050", "https://example.invalid:5050"],
        )

    def test_expand_socketio_cors_skips_empty_and_none(self):
        expanded = expand_socketio_cors_config_entries(["", "http://fixed:5000"], port=9999)
        self.assertEqual(expanded, ["http://fixed:5000"])

    def test_dashboard_reports_href_normalizes_leading_slash(self):
        self.assertEqual(
            dashboard_reports_href("p/run1/embed_model/json/x.json"), "/reports/p/run1/embed_model/json/x.json"
        )

    def test_json_sibling_resolves_beside_model_dir(self):
        md = Path("sec/p/run1/embed_model/md/sqli.md")
        self.assertEqual(
            json_sibling_for_format_artifact(md),
            Path("sec/p/run1/embed_model/json/sqli.json"),
        )

    def test_preferred_detail_prefers_existing_json_over_pdf(self):
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace

        from oasis.export.filenames import artifact_filename

        with tempfile.TemporaryDirectory() as tmp:
            self._run_preferred_detail_prefers_existing_json_over_pdf_test(
                Path, tmp, artifact_filename, SimpleNamespace
            )

    def _run_preferred_detail_prefers_existing_json_over_pdf_test(self, Path, tmp, artifact_filename, SimpleNamespace):
        base = Path(tmp) / "security_reports"

        model_key = "embed_model"
        md = base / "proj" / "20260101_120000" / model_key
        (md / "json").mkdir(parents=True)
        stem = "sql_injection"
        json_file = md / "json" / artifact_filename(stem, "json")
        json_file.write_text("{}", encoding="utf-8")
        (md / "pdf").mkdir(parents=True)
        pdf_file = md / "pdf" / artifact_filename(stem, "pdf")
        pdf_file.write_bytes(b"%PDF")

        report = SimpleNamespace(
            output_base_dir=base,
            current_model="embed_model",
            report_dirs={
                model_key: {
                    "json": md / "json",
                    "pdf": md / "pdf",
                    "md": md / "md",
                }
            },
        )
        rel, fmt = preferred_detail_relative_path_and_format(report, stem)
        self.assertEqual(fmt, "json")
        self.assertTrue(rel.endswith("/json/sql_injection.json"))

    def test_rewrite_preview_links_relative_pdf_to_reports(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            sec = Path(tmp) / "security_reports"
            md = sec / "run1" / "embed_model" / "md" / "_executive_summary.md"
            md.parent.mkdir(parents=True)
            (sec / "run1" / "embed_model" / "pdf").mkdir(parents=True)
            pdf = sec / "run1" / "embed_model" / "pdf" / "jwt_implementation_flaws.pdf"
            pdf.write_bytes(b"%PDF")

            html = '<p><a href="../pdf/jwt_implementation_flaws.pdf">Details</a></p>'
            out = rewrite_report_preview_anchor_hrefs(html, md, sec)
            self.assertIn('href="/reports/run1/embed_model/pdf/jwt_implementation_flaws.pdf"', out)

    def test_rewrite_preview_repairs_root_absolute_pdf_href(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            sec = Path(tmp) / "security_reports"
            md = sec / "run1" / "embed_model" / "md" / "_executive_summary.md"
            md.parent.mkdir(parents=True)
            (sec / "run1" / "embed_model" / "pdf").mkdir(parents=True)
            (sec / "run1" / "embed_model" / "pdf" / "jwt_implementation_flaws.pdf").write_bytes(b"%PDF")

            html = '<a href="/pdf/jwt_implementation_flaws.pdf">Details</a>'
            out = rewrite_report_preview_anchor_hrefs(html, md, sec)
            self.assertIn('href="/reports/run1/embed_model/pdf/jwt_implementation_flaws.pdf"', out)


if __name__ == "__main__":
    unittest.main()
