"""HTTP tests for dashboard assistant and source snippet routes."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from flask import Flask

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from oasis.config import OLLAMA_URL
from oasis.report import Report
from oasis.web import WebServer


class TestWebAssistantRoutes(unittest.TestCase):
    @staticmethod
    def _no_auth(f):
        return f

    def _make_server(self, base: Path):
        inp = base / "scan_root"
        inp.mkdir()
        (inp / "app.py").write_text("line1\nline2\nline3\n", encoding="utf-8")
        report = Report(str(inp), ["json"])
        server = WebServer(report, web_password="x", web_assistant_rag=False)
        mock_om = MagicMock()
        mock_om.chat.return_value = {"message": {"content": "assistant-reply"}}
        mock_om.get_effective_context_token_count.return_value = None
        mock_om.list_chat_model_names.return_value = []
        server._get_assistant_ollama_manager = lambda: mock_om
        return server, base

    def test_source_snippet_returns_slice(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.get("/api/source-snippet?path=app.py&start_line=1&end_line=2")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("lines"), ["line1", "line2"])

    def test_assistant_chat_returns_model_reply(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            # WebServer.__init__ already creates security_reports next to the scan root parent.
            rel = "rep.json"
            payload = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "t",
                "generated_at": "2026-01-01",
                "model_name": "m1",
                "vulnerability_name": "SQL Injection",
                "files": [],
                "stats": {"total_findings": 0},
            }
            (sec / rel).write_text(json.dumps(payload), encoding="utf-8")

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/chat",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": "Hello"}], "report_path": rel}
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("message"), "assistant-reply")
            self.assertEqual(data.get("visible_markdown"), "assistant-reply")
            self.assertIn("rag_unavailable", data)
            self.assertFalse(data.get("rag_unavailable"))
            sid = data.get("session_id")
            self.assertIsInstance(sid, str)
            self.assertEqual(len(sid), 36)

            meta = json.loads(client.get("/api/assistant/sessions?report_path=rep.json").get_data(as_text=True))
            self.assertEqual(len(meta), 1)
            self.assertEqual(meta[0]["session_id"], sid)

            doc = json.loads(
                client.get(f"/api/assistant/session?report_path=rep.json&session_id={sid}").get_data(as_text=True)
            )
            self.assertEqual(doc.get("schema_version"), 1)
            msgs = doc.get("messages")
            self.assertIsInstance(msgs, list)
            self.assertGreaterEqual(len(msgs), 2)

            del_resp = client.delete(
                "/api/assistant/session",
                data=json.dumps({"report_path": "rep.json", "session_id": sid}),
                content_type="application/json",
            )
            self.assertEqual(del_resp.status_code, 200)

    def test_assistant_chat_visible_and_thought_split(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "r2.json"
            payload = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "t",
                "generated_at": "2026-01-01",
                "model_name": "m1",
                "vulnerability_name": "XSS",
                "files": [],
                "stats": {"total_findings": 0},
            }
            (sec / rel).write_text(json.dumps(payload), encoding="utf-8")

            mock_om = MagicMock()
            mock_om.chat.return_value = {
                "message": {"content": "<think>plan</think>\nFinal."}
            }
            mock_om.get_effective_context_token_count.return_value = None
            server._get_assistant_ollama_manager = lambda: mock_om

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/chat",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": "q"}], "report_path": rel}
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("visible_markdown"), "Final.")
            self.assertEqual(data.get("thought_segments"), ["plan"])


class TestExecutiveAndAssistantMetaRoutes(unittest.TestCase):
    @staticmethod
    def _no_auth(f):
        return f

    def _make_server(self, base: Path):
        inp = base / "scan_root"
        inp.mkdir()
        report = Report(str(inp), ["json"])
        server = WebServer(report, web_password="x", web_assistant_rag=False)
        mock_om = MagicMock()
        mock_om.chat.return_value = {"message": {"content": "ok"}}
        mock_om.get_effective_context_token_count.return_value = None
        mock_om.list_chat_model_names.return_value = ["alpha", "beta"]
        server._get_assistant_ollama_manager = lambda: mock_om
        return server, base

    def test_chat_models_lists_tags(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.get("/api/assistant/chat-models")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("models"), ["alpha", "beta"])

    def test_executive_preview_meta_rolls_up_severity(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "run_a" / "json"
            run_md = sec / "run_a" / "md"
            run_json.mkdir(parents=True)
            run_md.mkdir(parents=True)
            exec_js = {
                "report_type": "executive_summary",
                "schema_version": 1,
                "model_name": "m-exec",
                "title": "exec",
            }
            vuln_js = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "v",
                "generated_at": "2026-01-01",
                "model_name": "m1",
                "vulnerability_name": "X",
                "files": [{"file_path": "app.py"}],
                "stats": {
                    "critical_risk": 1,
                    "high_risk": 2,
                    "medium_risk": 1,
                    "low_risk": 0,
                    "total_findings": 4,
                },
            }
            (run_json / "_executive_summary.json").write_text(json.dumps(exec_js), encoding="utf-8")
            (run_json / "vuln.json").write_text(json.dumps(vuln_js), encoding="utf-8")
            (run_md / "_executive_summary.md").write_text("# Executive\n", encoding="utf-8")

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            rel = "run_a/md/_executive_summary.md"
            resp = client.get(f"/api/executive-preview-meta?path={rel}")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("severity_counts", {}).get("critical"), 1)
            self.assertEqual(data.get("severity_counts", {}).get("high"), 2)
            self.assertEqual(data.get("vulnerability_report_files"), 1)
            vr = data.get("vulnerability_reports")
            self.assertIsInstance(vr, list)
            self.assertEqual(len(vr), 1)
            self.assertEqual(vr[0].get("relative_path"), "run_a/json/vuln.json")
            self.assertEqual(vr[0].get("label"), "X")

    def test_assistant_chat_aggregate_executive_summary(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "run_b" / "json"
            run_json.mkdir(parents=True)
            exec_js = {
                "report_type": "executive_summary",
                "schema_version": 1,
                "model_name": "agg-model",
                "title": "exec",
            }
            vuln_js = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "v",
                "generated_at": "2026-01-01",
                "model_name": "agg-model",
                "vulnerability_name": "Y",
                "files": [{"file_path": "scan_root/app.py"}],
                "stats": {"total_findings": 1},
            }
            (run_json / "_executive_summary.json").write_text(json.dumps(exec_js), encoding="utf-8")
            (run_json / "vuln.json").write_text(json.dumps(vuln_js), encoding="utf-8")

            mock_om = MagicMock()
            mock_om.chat.return_value = {"message": {"content": "aggregate-reply"}}
            mock_om.get_effective_context_token_count.return_value = None
            mock_om.list_chat_model_names.return_value = ["agg-model"]
            server._get_assistant_ollama_manager = lambda: mock_om

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            rel = "run_b/json/_executive_summary.json"
            resp = client.post(
                "/api/assistant/chat",
                data=json.dumps(
                    {
                        "messages": [{"role": "user", "content": "Summarize"}],
                        "report_path": rel,
                        "aggregate_model_json": True,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("message"), "aggregate-reply")
            self.assertTrue(data.get("assistant_aggregate"))
            self.assertEqual(data.get("system_budget_chars"), server._ASSISTANT_MAX_TOTAL_REPORT_CHARS)

    def test_assistant_chat_aggregate_finding_scope_adds_selected_finding_json(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "run_c" / "json"
            run_json.mkdir(parents=True)
            exec_js = {
                "report_type": "executive_summary",
                "schema_version": 1,
                "model_name": "agg-model",
                "title": "exec",
            }
            vuln_js = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "v",
                "generated_at": "2026-01-01",
                "model_name": "agg-model",
                "vulnerability_name": "ScopedVuln",
                "files": [
                    {
                        "file_path": "scan_root/app.py",
                        "chunk_analyses": [
                            {
                                "start_line": 1,
                                "end_line": 2,
                                "findings": [{"title": "InjectionBug", "severity": "High"}],
                            }
                        ],
                    }
                ],
                "stats": {"total_findings": 1},
            }
            (run_json / "_executive_summary.json").write_text(json.dumps(exec_js), encoding="utf-8")
            (run_json / "scoped.json").write_text(json.dumps(vuln_js), encoding="utf-8")

            mock_om = MagicMock()
            mock_om.chat.return_value = {"message": {"content": "aggregate-reply"}}
            mock_om.get_effective_context_token_count.return_value = None
            mock_om.list_chat_model_names.return_value = ["agg-model"]
            server._get_assistant_ollama_manager = lambda: mock_om

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            rel = "run_c/json/_executive_summary.json"
            scope_rel = "run_c/json/scoped.json"
            resp = client.post(
                "/api/assistant/chat",
                data=json.dumps(
                    {
                        "messages": [{"role": "user", "content": "Focus"}],
                        "report_path": rel,
                        "aggregate_model_json": True,
                        "finding_scope_report_path": scope_rel,
                        "file_index": 0,
                        "chunk_index": 0,
                        "finding_index": 0,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            mock_om.chat.assert_called_once()
            full_messages = mock_om.chat.call_args[0][1]
            system_prompt = full_messages[0]["content"]
            self.assertIn("SELECTED_FINDING_JSON", system_prompt)
            self.assertIn("InjectionBug", system_prompt)

    def test_report_json_synthetic_when_executive_json_file_missing(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "run_nomdjson" / "json"
            run_md = sec / "run_nomdjson" / "md"
            run_json.mkdir(parents=True)
            run_md.mkdir(parents=True)
            vuln_js = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "model_name": "from-vuln",
                "vulnerability_name": "V",
                "files": [],
                "stats": {},
            }
            (run_json / "only_vuln.json").write_text(json.dumps(vuln_js), encoding="utf-8")
            (run_md / "_executive_summary.md").write_text("# Executive\n", encoding="utf-8")

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            rel = "run_nomdjson/json/_executive_summary.json"
            resp = client.get(f"/api/report-json/{rel}")
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("report_type"), "executive_summary")
            self.assertEqual(data.get("model_name"), "from-vuln")

    def test_assistant_chat_aggregate_without_executive_json_on_disk(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "run_aggmd" / "json"
            run_md = sec / "run_aggmd" / "md"
            run_json.mkdir(parents=True)
            run_md.mkdir(parents=True)
            vuln_js = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "model_name": "agg-md",
                "vulnerability_name": "Z",
                "files": [],
                "stats": {},
            }
            (run_json / "v.json").write_text(json.dumps(vuln_js), encoding="utf-8")
            (run_md / "_executive_summary.md").write_text("# Executive\n", encoding="utf-8")

            mock_om = MagicMock()
            mock_om.chat.return_value = {"message": {"content": "ok-md"}}
            mock_om.get_effective_context_token_count.return_value = None
            mock_om.list_chat_model_names.return_value = ["agg-md"]
            server._get_assistant_ollama_manager = lambda: mock_om

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            rel = "run_aggmd/json/_executive_summary.json"
            resp = client.post(
                "/api/assistant/chat",
                data=json.dumps(
                    {
                        "messages": [{"role": "user", "content": "Hi"}],
                        "report_path": rel,
                        "aggregate_model_json": True,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("message"), "ok-md")


class TestResolveAssistantOllamaUrl(unittest.TestCase):
    def test_non_empty_web_url_wins_after_strip(self):
        server = WebServer.__new__(WebServer)
        server.web_ollama_url = "  http://web-only  "
        server._default_ollama_url = "http://default"
        with patch.dict(os.environ, {"OASIS_WEB_OLLAMA_URL": "http://env"}):
            self.assertEqual(server._resolve_assistant_ollama_url(), "http://web-only")

    def test_skips_whitespace_only_sources(self):
        server = WebServer.__new__(WebServer)
        server.web_ollama_url = "  \t\n  "
        server._default_ollama_url = "   "
        with patch.dict(os.environ, {"OASIS_WEB_OLLAMA_URL": " \n "}):
            self.assertEqual(server._resolve_assistant_ollama_url(), str(OLLAMA_URL).strip())


if __name__ == "__main__":
    unittest.main()
