"""Regression: WebServer must expose ``collect_report_data`` (dashboard index refresh)."""

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.report import Report  # noqa: E402
from oasis.web import WebServer, normalize_dashboard_project_key  # noqa: E402


class TestNormalizeDashboardProjectKey(unittest.TestCase):
    def test_strips_and_lowercases(self):
        self.assertEqual(normalize_dashboard_project_key(" MyApp "), "myapp")

    def test_empty_when_missing(self):
        self.assertEqual(normalize_dashboard_project_key(None), "")
        self.assertEqual(normalize_dashboard_project_key(""), "")


class TestWebServerCollectReportData(unittest.TestCase):
    def test_collect_report_data_populates_report_data_and_global_stats(self):
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "proj"
            scan.mkdir()
            sec = scan.parent / "security_reports"
            sec.mkdir()
            run_dir = sec / "20100101_120000" / "embed_m" / "json"
            run_dir.mkdir(parents=True)
            run_dir.joinpath("sqli.json").write_text(
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
                        "stats": {
                            "high_risk": 1,
                            "medium_risk": 0,
                            "low_risk": 0,
                            "critical_risk": 0,
                            "total_findings": 2,
                            "files_analyzed": 3,
                        },
                        "language": "en",
                        "project": "demo",
                    }
                ),
                encoding="utf-8",
            )

            ws = WebServer(Report(str(scan), ["json"]))
            self.assertTrue(hasattr(ws, "collect_report_data"))
            self.assertTrue(callable(getattr(ws, "collect_report_data")))

            ws.collect_report_data()

            self.assertIsInstance(ws.report_data, list)
            self.assertEqual(len(ws.report_data), 1)
            self.assertEqual(ws.report_data[0].get("format"), "json")

            self.assertIsNotNone(ws.global_stats)
            self.assertIn("total_reports", ws.global_stats)
            self.assertIn("risk_summary", ws.global_stats)
            self.assertGreaterEqual(ws.global_stats["total_reports"], 1)

    def test_collect_report_data_single_flights_concurrent_callers(self):
        """Concurrent collect_report_data callers share one directory walk (issue: first-load contention)."""
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "proj"
            scan.mkdir()
            (scan.parent / "security_reports").mkdir(exist_ok=True)
            ws = WebServer(Report(str(scan), ["json"]))

            walks = {"n": 0}
            walk_lock = threading.Lock()
            real_walk = ws._collect_reports_from_directories
            first_walk_started = threading.Event()
            release_first_walk = threading.Event()

            def counting_walk():
                with walk_lock:
                    walks["n"] += 1
                if walks["n"] == 1:
                    first_walk_started.set()
                    # Hold the first walk open so the other two callers are
                    # already parked on the collect lock (their entry epoch is
                    # still 0) when the epoch is finally bumped.
                    release_first_walk.wait(timeout=5)
                return real_walk()

            with patch.object(ws, "_collect_reports_from_directories", counting_walk):
                results = [False, False, False]

                def worker(i):
                    ws.collect_report_data()
                    results[i] = True

                threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
                for th in threads:
                    th.start()
                self.assertTrue(first_walk_started.wait(timeout=5), "first collect never started")
                time.sleep(0.1)  # let the two remaining callers read epoch 0 and park on the lock
                release_first_walk.set()
                for th in threads:
                    th.join()

                self.assertEqual(walks["n"], 1)
                self.assertEqual(results, [True, True, True])
                self.assertIsInstance(ws.report_data, list)

                ws.collect_report_data()
                self.assertEqual(walks["n"], 2, "sequential caller after the wave must collect again")

    def test_collect_report_data_recollects_when_tree_changes(self):
        """A collect skipped by single-flight still yields data at least as fresh as caller entry."""
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "proj"
            scan.mkdir()
            (scan.parent / "security_reports").mkdir(exist_ok=True)
            ws = WebServer(Report(str(scan), ["json"]))

            ws.collect_report_data()
            self.assertEqual(ws.report_data, [])

            run_dir = ws.security_dir / "20100101_120000" / "embed_m" / "json"
            run_dir.mkdir(parents=True)
            run_dir.joinpath("sqli.json").write_text(
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
                        "stats": {
                            "high_risk": 1,
                            "medium_risk": 0,
                            "low_risk": 0,
                            "critical_risk": 0,
                            "total_findings": 2,
                            "files_analyzed": 3,
                        },
                        "language": "en",
                        "project": "demo",
                    }
                ),
                encoding="utf-8",
            )
            ws.collect_report_data()
            self.assertEqual(len(ws.report_data or []), 1)

    def test_run_invokes_collect_report_data(self):
        """``WebServer.run`` must call ``collect_report_data`` before binding the socket (regression)."""
        with tempfile.TemporaryDirectory() as td:
            scan = Path(td) / "proj"
            scan.mkdir()
            (scan.parent / "security_reports").mkdir(exist_ok=True)
            ws = WebServer(Report(str(scan), ["json"]))

            invoked = 0
            real_collect = WebServer.collect_report_data

            def tracking_collect_report_data(self) -> None:
                nonlocal invoked
                invoked += 1
                real_collect(self)

            with patch.object(WebServer, "collect_report_data", tracking_collect_report_data):
                with patch("oasis.web.SocketIO") as mock_socketio_cls:
                    mock_socketio_cls.return_value = MagicMock()
                    with patch.object(ws, "register_routes", lambda app, server, login_required: app):
                        with patch.object(ws, "_register_socket_handlers"):
                            with patch.object(ws, "_start_progress_monitor"):
                                ws.run()

            self.assertEqual(invoked, 1)


if __name__ == "__main__":
    unittest.main()
