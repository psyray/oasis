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
