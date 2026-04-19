"""Tests for pure dashboard helper functions."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.dashboard import dashboard_format_display_order, expand_socketio_cors_config_entries


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


if __name__ == "__main__":
    unittest.main()
