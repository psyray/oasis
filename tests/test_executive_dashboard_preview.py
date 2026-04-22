"""Executive markdown preview augmentation (TOC in modal)."""

import unittest

from oasis.helpers.executive.dashboard_preview import augment_executive_markdown_preview_html


class TestExecutiveDashboardPreview(unittest.TestCase):
    def test_executive_toc_matches_vulnerability_preview_structure(self):
        html = "<body><h2>Overview</h2><p>x</p><h2>Models Used</h2><p>y</p></body>"
        out = augment_executive_markdown_preview_html(html)
        self.assertIn("report-toc-title", out)
        self.assertIn("Table of contents", out)
        self.assertIn('aria-label="Table of contents"', out)
        self.assertIn("report-toc-icon", out)
        self.assertIn("report-toc-label", out)
        self.assertTrue("📋" in out or "🤖" in out)
        self.assertIn("report-return-top", out)
        self.assertIn("report-return-top-link", out)
        self.assertIn("Return to table of contents", out)

    def test_return_to_toc_single_insert_when_h2_and_h3_share_next_boundary(self):
        """Several headings may target the same following heading (insert_before once)."""
        html = """<body>
<h2 id="scan">Scan Progress</h2><p>status</p>
<h3 id="pipe">Pipeline phases</h3><table><tr><td>row</td></tr></table>
<h2 id="after">After</h2><p>more</p>
</body>"""
        out = augment_executive_markdown_preview_html(html)
        # Deduped: one paragraph before shared boundary + one after last heading;
        # without dedupe of ``insert_before``, two paragraphs stack before ``after``.
        self.assertEqual(out.count('class="report-return-top"'), 2)


if __name__ == "__main__":
    unittest.main()
