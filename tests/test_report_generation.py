"""Tests for report generation edge cases."""

import tempfile
import unittest
from pathlib import Path

from oasis.report import Report


class TestReportGenerateAndSave(unittest.TestCase):
    def test_generate_and_save_report_is_no_op_without_markdown_format(self):
        """Requesting only JSON must not crash when the helper expects markdown.

        Regression: ``_generate_and_save_report`` used to do
        ``output_files['md']`` unconditionally, raising ``KeyError: 'md'`` when
        ``output_format`` did not include ``md``.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = Report(
                input_path=tmp,
                output_format=["json"],
                current_model="test-model",
            )
            report.create_report_directories(tmp, models=["test-model"])

            # No md key because the user asked for json only.
            output_files = report.filter_output_files("_executive_summary")
            self.assertNotIn("md", output_files)

            # Should not raise.
            report._generate_and_save_report(
                output_files,
                ["# Executive Summary", "Test content"],
                report_type="Executive Summary",
            )

    def test_generate_and_save_report_writes_markdown_when_requested(self):
        """When md is requested, the report is written and converted."""
        with tempfile.TemporaryDirectory() as tmp:
            report = Report(
                input_path=tmp,
                output_format=["json", "md"],
                current_model="test-model",
            )
            report.create_report_directories(tmp, models=["test-model"])

            output_files = report.filter_output_files("_executive_summary")
            self.assertIn("md", output_files)

            report._generate_and_save_report(
                output_files,
                ["# Executive Summary", "Test content"],
                report_type="Executive Summary",
            )

            self.assertTrue(output_files["md"].is_file())
            content = output_files["md"].read_text()
            self.assertIn("# Executive Summary", content)
            self.assertIn("Test content", content)


if __name__ == "__main__":
    unittest.main()
