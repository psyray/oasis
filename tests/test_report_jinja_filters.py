"""Tests for Jinja filters used by report HTML templates."""

import unittest

from jinja2 import Environment

from oasis.helpers.report_jinja_filters import audit_decimal_places, register_report_template_filters


class TestReportJinjaFilters(unittest.TestCase):
    def test_audit_decimal_places_formats_and_handles_none(self) -> None:
        self.assertEqual(audit_decimal_places(1.23456, 3), "1.235")
        self.assertEqual(audit_decimal_places(1.2345, 1), "1.2")
        self.assertEqual(audit_decimal_places(None, 3), "")

    def test_register_report_template_filters_exposes_audit_decimal(self) -> None:
        env = Environment()
        register_report_template_filters(env)
        tmpl = env.from_string("{{ x | audit_decimal(3) }}")
        self.assertEqual(tmpl.render(x=0.5), "0.500")


if __name__ == "__main__":
    unittest.main()
