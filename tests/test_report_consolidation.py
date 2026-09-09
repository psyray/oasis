"""Tests for the consolidated multi-model report (oasis.helpers.report_consolidation)."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.helpers.report_consolidation import (
    build_consolidated_digest,
    collect_model_findings,
    group_findings,
    write_consolidated_report,
)
from oasis.schemas.consolidated_report import ConsolidatedFindingGroup


def _vuln_doc(
    model: str,
    *,
    vuln_name: str = "SQL Injection",
    file_path: str = "app.py",
    title: str = "Finding",
    severity: str = "High",
    snippet: str = "cur.execute(sql)",
) -> dict:
    """Minimal canonical vulnerability document for consolidation tests."""
    return {
        "report_type": "vulnerability",
        "model_name": model,
        "vulnerability_name": vuln_name,
        "title": title,
        "files": [
            {
                "file_path": file_path,
                "chunk_analyses": [
                    {
                        "findings": [
                            {"title": title, "severity": severity, "vulnerable_code": snippet}
                        ]
                    }
                ],
            }
        ],
    }


class _RunDir:
    """Temp run directory holding one ``json/<name>.json`` document per model."""

    path: Path

    def __init__(self, docs_by_model: dict[str, list[dict]]) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)
        for model, docs in docs_by_model.items():
            json_dir = self.path / model / "json"
            json_dir.mkdir(parents=True)
            for index, doc in enumerate(docs):
                (json_dir / f"report_{index}.json").write_text(json.dumps(doc), encoding="utf-8")

    def cleanup(self) -> None:
        shutil.rmtree(self._tmp.name)

    def __enter__(self) -> _RunDir:
        return self

    def __exit__(self, *_args: object) -> None:
        self.cleanup()


class TestGroupFindings(unittest.TestCase):
    def test_shared_fingerprint_merges_models(self):
        refs_by_model = {
            "m1": [{"fingerprint": "fp-a", "file_path": "a.py", "vulnerability_name": "XSS", "title": "A", "severity": "High", "snippet": "s"}],
            "m2": [{"fingerprint": "fp-a", "file_path": "a.py", "vulnerability_name": "XSS", "title": "A2", "severity": "Critical", "snippet": "s"}],
        }
        groups = group_findings(refs_by_model)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].confirming_models, ["m1", "m2"])
        self.assertEqual(groups[0].severity_by_model, {"m1": "High", "m2": "Critical"})

    def test_single_model_group_sorted_last(self):
        refs_by_model = {
            "m1": [
                {"fingerprint": "fp-unique", "file_path": "b.py", "vulnerability_name": "SQL Injection", "title": "U", "severity": "Low", "snippet": "u"},
                {"fingerprint": "fp-shared", "file_path": "a.py", "vulnerability_name": "XSS", "title": "S", "severity": "High", "snippet": "s"},
            ],
            "m2": [{"fingerprint": "fp-shared", "file_path": "a.py", "vulnerability_name": "XSS", "title": "S", "severity": "High", "snippet": "s"}],
        }
        groups = group_findings(refs_by_model)
        self.assertEqual([g.fingerprint for g in groups], ["fp-shared", "fp-unique"])

    def test_empty_fingerprint_refs_skipped(self):
        groups = group_findings({"m1": [{"fingerprint": "", "file_path": "a.py"}]})
        self.assertEqual(groups, [])


class TestCollectModelFindings(unittest.TestCase):
    def test_docs_grouped_by_model_name(self):
        with _RunDir(
            {
                "m1": [_vuln_doc("m1")],
                "m2": [_vuln_doc("m2"), _vuln_doc("m2", vuln_name="XSS")],
            }
        ) as run:
            refs_by_model = collect_model_findings(run.path)
        self.assertEqual(sorted(refs_by_model), ["m1", "m2"])
        self.assertEqual(len(refs_by_model["m2"]), 2)
        self.assertIn("fingerprint", refs_by_model["m1"][0])

    def test_non_vulnerability_documents_ignored(self):
        with _RunDir({"m1": [_vuln_doc("m1")]}) as run:
            (run.path / "m1" / "json" / "audit.json").write_text(
                '{"report_type": "audit", "model_name": "m1"}', encoding="utf-8"
            )
            refs_by_model = collect_model_findings(run.path)
        self.assertEqual(sorted(refs_by_model), ["m1"])
        self.assertEqual(len(refs_by_model["m1"]), 1)


class TestBuildConsolidatedDigest(unittest.TestCase):
    def _groups(self, count: int) -> list[ConsolidatedFindingGroup]:
        return [
            ConsolidatedFindingGroup(
                fingerprint=f"fp-{i}",
                file_path=f"f{i}.py",
                vulnerability_name=f"V{i}",
                title=f"T{i}",
                severity_by_model={"m1": "High"},
                confirming_models=["m1"],
            )
            for i in range(count)
        ]

    def test_digest_under_budget_keeps_all_groups(self):
        digest = build_consolidated_digest(self._groups(3), max_chars=100000)
        self.assertIn('"truncated": false', digest)
        self.assertIn("V2", digest)

    def test_digest_respects_max_chars(self):
        digest = build_consolidated_digest(self._groups(50), max_chars=600)
        self.assertLessEqual(len(digest), 600)
        self.assertIn('"truncated": true', digest)


class TestWriteConsolidatedReport(unittest.TestCase):
    def test_single_model_run_returns_none(self):
        with _RunDir({"m1": [_vuln_doc("m1")]}) as run:
            self.assertIsNone(write_consolidated_report(run.path))

    def test_missing_run_dir_returns_none(self):
        self.assertIsNone(write_consolidated_report(Path("/nonexistent-run-dir")))

    def test_two_models_merged_without_narrative(self):
        with _RunDir(
            {
                "m1": [_vuln_doc("m1"), _vuln_doc("m1", vuln_name="XSS", file_path="b.py")],
                "m2": [_vuln_doc("m2")],
            }
        ) as run:
            doc = write_consolidated_report(run.path, source_models=["m1", "m2"])

            self.assertIsNotNone(doc)
            assert doc is not None  # type narrowing for the checker
            self.assertEqual(doc["counts"]["total_groups"], 2)
            self.assertEqual(doc["counts"]["confirmed_by_all"], 1)
            self.assertEqual(doc["counts"]["single_model"], 1)
            self.assertIsNone(doc["narrative"])
            self.assertEqual(doc["source_models"], ["m1", "m2"])
            consolidated = run.path / "consolidated" / "consolidated_report.json"
            self.assertTrue(consolidated.exists())
            self.assertTrue((run.path / "consolidated" / "consolidated_report.md").exists())
            self.assertEqual(consolidated.read_text(encoding="utf-8").count('"fingerprint"'), 2)

    def test_source_models_filter_excludes_strangers(self):
        with _RunDir({"m1": [_vuln_doc("m1")], "m2": [_vuln_doc("m2")], "m3": [_vuln_doc("m3")]}) as run:
            doc = write_consolidated_report(run.path, source_models=["m1", "m2"])
            assert doc is not None  # type narrowing for the checker
            self.assertEqual(doc["source_models"], ["m1", "m2"])

    def test_llm_narrative_success(self):
        narrative = {"overview": "All good.", "priorities_markdown": "- Fix XSS", "guidance_markdown": "Escape output."}
        backend = MagicMock()
        backend.chat.return_value = {"message": {"content": json.dumps(narrative)}}
        with _RunDir({"m1": [_vuln_doc("m1")], "m2": [_vuln_doc("m2")]}) as run:
            doc = write_consolidated_report(run.path, backend=backend, report_model="reporter")
            assert doc is not None  # type narrowing for the checker

            self.assertIsNotNone(doc["narrative"])
            self.assertEqual(doc["narrative"]["overview"], "All good.")
            # Structured output: the schema travels with the chat call
            self.assertEqual(backend.chat.call_args.kwargs["model"], "reporter")
            self.assertIn("format", backend.chat.call_args.kwargs)

    def test_llm_narrative_failure_keeps_document(self):
        backend = MagicMock()
        backend.chat.return_value = {"message": {"content": "not-json"}}
        with _RunDir({"m1": [_vuln_doc("m1")], "m2": [_vuln_doc("m2")]}) as run:
            doc = write_consolidated_report(run.path, backend=backend, report_model="reporter")
            assert doc is not None  # type narrowing for the checker

            self.assertIsNone(doc["narrative"])
            self.assertTrue((run.path / "consolidated" / "consolidated_report.json").exists())

    def test_llm_exception_keeps_document(self):
        backend = MagicMock()
        backend.chat.side_effect = RuntimeError("boom")
        with _RunDir({"m1": [_vuln_doc("m1")], "m2": [_vuln_doc("m2")]}) as run:
            doc = write_consolidated_report(run.path, backend=backend, report_model="reporter")
            assert doc is not None  # type narrowing for the checker

            self.assertIsNone(doc["narrative"])
            self.assertTrue((run.path / "consolidated" / "consolidated_report.md").exists())

    def test_document_round_trip(self):
        from oasis.schemas import ConsolidatedReportDocument

        with _RunDir({"m1": [_vuln_doc("m1")], "m2": [_vuln_doc("m2")]}) as run:
            doc = write_consolidated_report(run.path)
            assert doc is not None  # type narrowing for the checker
            reparsed = ConsolidatedReportDocument.model_validate_json(
                (run.path / "consolidated" / "consolidated_report.json").read_text(encoding="utf-8")
            )
        self.assertEqual(reparsed.report_type, "consolidated")
        self.assertEqual(len(reparsed.groups), doc["counts"]["total_groups"])


class TestConsolidatedHtmlRender(unittest.TestCase):
    def test_render_report_html_from_json_payload(self):
        from unittest.mock import MagicMock

        from oasis.report import Report

        with _RunDir({"m1": [_vuln_doc("m1")], "m2": [_vuln_doc("m2")]}) as run:
            doc = write_consolidated_report(
                run.path,
                backend=MagicMock(
                    chat=MagicMock(
                        return_value={
                            "message": {"content": json.dumps(
                                {"overview": "All good.", "priorities_markdown": "- Fix XSS", "guidance_markdown": "Escape output."}
                            )}
                        }
                    )
                ),
                report_model="reporter",
            )
            assert doc is not None  # type narrowing for the checker
            report = Report(str(run.path), ["json"])
            html = report.render_report_html_from_json_payload(doc)

        self.assertIn("Consolidated multi-model report", html)
        self.assertIn("Confirmed by all models", html)
        self.assertIn("Single-model findings", html)
        self.assertIn("All good.", html)
        self.assertIn("Fix XSS", html)


class TestConsolidatedHtmlRenderNarrativeFailure(unittest.TestCase):
    def test_render_html_without_narrative(self):
        from oasis.report import Report

        with _RunDir({"m1": [_vuln_doc("m1")], "m2": [_vuln_doc("m2")]}) as run:
            doc = write_consolidated_report(run.path)
            assert doc is not None  # type narrowing for the checker
            report = Report(str(run.path), ["json"])
            html = report.render_report_html_from_json_payload(doc)

        self.assertIn("Narrative unavailable", html)
        self.assertIn("Confirmed by all models", html)


if __name__ == "__main__":
    unittest.main()