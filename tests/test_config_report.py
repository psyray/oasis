"""Tests for REPORT-related configuration validation."""

import unittest

from oasis.config import validate_report_dashboard_formats


class TestValidateReportDashboardFormats(unittest.TestCase):
    def test_detects_unknown_dashboard_order_entry(self):
        with self.assertLogs("oasis.config", level="WARNING"):
            bad = validate_report_dashboard_formats(
                {
                    "OUTPUT_FORMATS": ["json", "md"],
                    "DASHBOARD_FORMAT_DISPLAY_ORDER": ["html", "json"],
                }
            )
        self.assertEqual(bad, ["html"])

    def test_empty_when_consistent(self):
        bad = validate_report_dashboard_formats(
            {
                "OUTPUT_FORMATS": ["json", "md"],
                "DASHBOARD_FORMAT_DISPLAY_ORDER": ["md", "json"],
            }
        )
        self.assertEqual(bad, [])

    def test_case_insensitive_match(self):
        bad = validate_report_dashboard_formats(
            {
                "OUTPUT_FORMATS": ["json", "SARIF"],
                "DASHBOARD_FORMAT_DISPLAY_ORDER": ["sarif", "json"],
            }
        )
        self.assertEqual(bad, [])
