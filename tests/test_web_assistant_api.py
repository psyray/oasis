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
        mock_om.get_effective_context_token_count_with_source.return_value = (None, "")
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
            self.assertEqual(doc.get("schema_version"), 3)
            self.assertIn("model_branches", doc)
            msgs = doc.get("messages")
            self.assertIsInstance(msgs, list)
            self.assertGreaterEqual(len(msgs), 2)

            del_resp = client.delete(
                "/api/assistant/session",
                data=json.dumps({"report_path": "rep.json", "session_id": sid}),
                content_type="application/json",
            )
            self.assertEqual(del_resp.status_code, 200)

    @staticmethod
    def _parse_ndjson_events(raw: bytes):
        events = []
        for line in raw.decode("utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line))
        return events

    def test_assistant_chat_stream_yields_events_and_persists_reply(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "rep_stream.json"
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

            mock_om = server._get_assistant_ollama_manager()
            mock_om.chat_stream.return_value = iter(
                [
                    {"message": {"content": "Hel"}},
                    {"message": {"content": "lo, "}},
                    {"message": {"content": "world"}},
                    {"done": True},
                ]
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/chat-stream",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": "hi"}], "report_path": rel}
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(
                resp.mimetype.startswith("application/x-ndjson"),
                resp.mimetype,
            )

            events = self._parse_ndjson_events(resp.get_data())
            self.assertGreaterEqual(len(events), 3)
            self.assertEqual(events[0].get("type"), "start")
            deltas = [e for e in events if e.get("type") == "delta"]
            self.assertEqual(
                [d.get("content") for d in deltas], ["Hel", "lo, ", "world"]
            )
            # New ``channel`` field tags each delta as content vs thinking.
            self.assertTrue(all(d.get("channel") == "content" for d in deltas))
            done = events[-1]
            self.assertEqual(done.get("type"), "done")
            self.assertEqual(done.get("message"), "Hello, world")
            self.assertEqual(done.get("visible_markdown"), "Hello, world")
            sid = done.get("session_id")
            self.assertIsInstance(sid, str)
            self.assertEqual(len(sid), 36)

            doc = json.loads(
                client.get(
                    f"/api/assistant/session?report_path={rel}&session_id={sid}"
                ).get_data(as_text=True)
            )
            msgs = doc.get("messages")
            self.assertIsInstance(msgs, list)
            assistant_entries = [m for m in msgs if m.get("role") == "assistant"]
            self.assertTrue(assistant_entries)
            self.assertEqual(assistant_entries[-1].get("content"), "Hello, world")

    def test_assistant_chat_stream_exposes_native_thinking_channel(self):
        """``message.thinking`` from ollama is forwarded as its own delta channel
        and surfaces in ``thought_segments`` so the UI can render reasoning
        separately from the visible answer.
        """
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "rep_stream_thinking.json"
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

            mock_om = server._get_assistant_ollama_manager()
            mock_om.chat_stream.return_value = iter(
                [
                    {"message": {"thinking": "Analyzing ", "content": ""}},
                    {"message": {"thinking": "the snippet.", "content": ""}},
                    {"message": {"thinking": "", "content": "Hello"}},
                    {"message": {"thinking": "", "content": " world"}},
                    {"done": True},
                ]
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/chat-stream",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": "hi"}], "report_path": rel}
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            events = self._parse_ndjson_events(resp.get_data())

            deltas = [e for e in events if e.get("type") == "delta"]
            thinking_deltas = [d for d in deltas if d.get("channel") == "thinking"]
            content_deltas = [d for d in deltas if d.get("channel") == "content"]
            self.assertEqual(
                [d.get("content") for d in thinking_deltas],
                ["Analyzing ", "the snippet."],
            )
            self.assertEqual(
                [d.get("content") for d in content_deltas], ["Hello", " world"]
            )

            done = events[-1]
            self.assertEqual(done.get("type"), "done")
            self.assertEqual(done.get("message"), "Hello world")
            self.assertEqual(done.get("visible_markdown"), "Hello world")
            self.assertIn("Analyzing the snippet.", done.get("thought_segments", []))

    def test_assistant_chat_stream_strips_harmony_tags_from_visible(self):
        """Raw ``<|channel>thought <channel|>`` tags emitted by gpt-oss style
        models must not leak into ``visible_markdown``.
        """
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "rep_stream_harmony.json"
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

            mock_om = server._get_assistant_ollama_manager()
            mock_om.chat_stream.return_value = iter(
                [
                    {"message": {"content": "<|channel>>thought <channel|>"}},
                    {"message": {"content": "Some reasoning here.\n\n"}},
                    {"message": {"content": "The actual answer."}},
                    {"done": True},
                ]
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/chat-stream",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": "q"}], "report_path": rel}
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            events = self._parse_ndjson_events(resp.get_data())
            done = events[-1]
            self.assertEqual(done.get("type"), "done")
            self.assertNotIn("<|channel", done.get("visible_markdown", ""))
            self.assertNotIn("<channel|>", done.get("visible_markdown", ""))
            self.assertEqual(done.get("visible_markdown"), "The actual answer.")
            self.assertIn("Some reasoning here.", done.get("thought_segments", []))

    def test_assistant_chat_stream_emits_error_event_on_ollama_failure(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "rep_stream_err.json"
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

            mock_om = server._get_assistant_ollama_manager()

            def _raise(*_args, **_kwargs):
                raise RuntimeError("boom")

            mock_om.chat_stream.side_effect = _raise

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/chat-stream",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": "hi"}], "report_path": rel}
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            events = self._parse_ndjson_events(resp.get_data())
            self.assertEqual(events[0].get("type"), "start")
            self.assertEqual(events[-1].get("type"), "error")
            self.assertIn("RuntimeError", events[-1].get("error", ""))

    def test_assistant_chat_stream_emits_error_when_stream_yields_error_chunk(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "rep_stream_chunk_err.json"
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

            mock_om = server._get_assistant_ollama_manager()
            mock_om.chat_stream.return_value = iter(
                [
                    {"message": {"content": "x"}},
                    {"type": "error", "error": "mid-stream failure"},
                ]
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/chat-stream",
                data=json.dumps(
                    {"messages": [{"role": "user", "content": "hi"}], "report_path": rel}
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            events = self._parse_ndjson_events(resp.get_data())
            self.assertEqual(events[0].get("type"), "start")
            self.assertEqual(events[-1].get("type"), "error")
            self.assertIn("mid-stream", events[-1].get("error", ""))
            dones = [e for e in events if e.get("type") == "done"]
            self.assertFalse(dones)

            sid = events[0].get("session_id")
            self.assertIsInstance(sid, str)
            doc = json.loads(
                client.get(
                    f"/api/assistant/session?report_path={rel}&session_id={sid}"
                ).get_data(as_text=True)
            )
            msgs = doc.get("messages")
            self.assertIsInstance(msgs, list)
            assistant_entries = [m for m in msgs if m.get("role") == "assistant"]
            self.assertTrue(assistant_entries)
            self.assertEqual(assistant_entries[-1].get("content"), "x")

    def test_assistant_chat_injects_finding_validation_json(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "repv.json"
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

            from oasis.helpers.assistant.web.persistence import (
                finding_validation_storage_key,
                merge_finding_validation_into_session,
                new_session_id,
            )

            sid = new_session_id()
            fk0 = finding_validation_storage_key("", 0, 0, 0)
            assert fk0 is not None
            merge_finding_validation_into_session(
                sec,
                rel,
                sid,
                "m1",
                {
                    "vulnerability_name": "SQL Injection",
                    "family": "flow",
                    "status": "confirmed_exploitable",
                    "confidence": 0.88,
                    "summary": "deterministic summary",
                },
                "SQL Injection",
                finding_key=fk0,
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            mock_om = server._get_assistant_ollama_manager()
            resp = client.post(
                "/api/assistant/chat",
                data=json.dumps(
                    {
                        "messages": [{"role": "user", "content": "PoC?"}],
                        "report_path": rel,
                        "model": "m1",
                        "session_id": sid,
                        "file_index": 0,
                        "chunk_index": 0,
                        "finding_index": 0,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            mock_om.chat.assert_called()
            full_messages = mock_om.chat.call_args[0][1]
            system_prompt = full_messages[0]["content"]
            self.assertIn("FINDING_VALIDATION_JSON", system_prompt)
            self.assertIn("confirmed_exploitable", system_prompt)

    def test_assistant_chat_survives_validation_context_builder_failure(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "rep_ctx_fail.json"
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
            mock_om = server._get_assistant_ollama_manager()

            with patch(
                "oasis.web.load_chat_session", side_effect=RuntimeError("boom")
            ):
                resp = client.post(
                    "/api/assistant/chat",
                    data=json.dumps(
                        {
                            "messages": [{"role": "user", "content": "hello"}],
                            "report_path": rel,
                            "model": "m1",
                            "session_id": "abcd1234abcd1234abcd1234abcd1234",
                        }
                    ),
                    content_type="application/json",
                )

            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("message"), "assistant-reply")
            mock_om.chat.assert_called_once()

    def test_assistant_chat_uses_local_root_when_report_analysis_root_is_stale(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            inp = base / "scan_root"
            inp.mkdir()
            report = Report(str(inp), ["json"])
            server = WebServer(report, web_password="x", web_assistant_rag=True)
            mock_om = MagicMock()
            mock_om.chat.return_value = {"message": {"content": "assistant-reply"}}
            mock_om.get_effective_context_token_count.return_value = None
            mock_om.get_effective_context_token_count_with_source.return_value = (None, "")
            mock_om.list_chat_model_names.return_value = []
            server._get_assistant_ollama_manager = lambda: mock_om

            sec = base / "security_reports"
            rel = "rep_stale_root.json"
            payload = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "t",
                "generated_at": "2026-01-01",
                "model_name": "m1",
                "vulnerability_name": "SQL Injection",
                "analysis_root": "/root/code-audit/Tchatche/Code",
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
                    {
                        "messages": [{"role": "user", "content": "Hello"}],
                        "report_path": rel,
                        "model": "m1",
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data.get("message"), "assistant-reply")

    def test_assistant_session_branch_persists_messages(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "branch.json"
            payload = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "t",
                "generated_at": "2026-01-01",
                "model_name": "mx",
                "vulnerability_name": "SQL Injection",
                "files": [],
                "stats": {"total_findings": 0},
            }
            (sec / rel).write_text(json.dumps(payload), encoding="utf-8")

            from oasis.helpers.assistant.web.persistence import new_session_id, save_chat_session

            sid = new_session_id()
            save_chat_session(
                sec,
                rel,
                sid,
                [{"role": "user", "content": "old", "at": "t"}],
                "mx",
                "SQL Injection",
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/session-branch",
                data=json.dumps(
                    {
                        "report_path": rel,
                        "session_id": sid,
                        "model": "mx",
                        "messages": [
                            {"role": "user", "content": "u1", "at": "t"},
                            {"role": "assistant", "content": "a1", "at": "t"},
                        ],
                        "vulnerability_name": "SQL Injection",
                        "set_as_active": True,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            doc = json.loads(
                client.get(f"/api/assistant/session?report_path={rel}&session_id={sid}").get_data(as_text=True)
            )
            self.assertEqual(doc["model_branches"]["mx"]["messages"][0]["content"], "u1")

    def test_assistant_session_branch_accepts_empty_messages(self):
        """Model switch may flush an empty thread; session-branch must persist []."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "branch_empty.json"
            payload = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "t",
                "generated_at": "2026-01-01",
                "model_name": "m-a",
                "vulnerability_name": "XSS",
                "files": [],
                "stats": {"total_findings": 0},
            }
            (sec / rel).write_text(json.dumps(payload), encoding="utf-8")

            from oasis.helpers.assistant.web.persistence import new_session_id, save_chat_session

            sid = new_session_id()
            save_chat_session(
                sec,
                rel,
                sid,
                [{"role": "user", "content": "hi", "at": "t"}],
                "m-a",
                "XSS",
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/session-branch",
                data=json.dumps(
                    {
                        "report_path": rel,
                        "session_id": sid,
                        "model": "m-a",
                        "messages": [],
                        "vulnerability_name": "XSS",
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            doc = json.loads(
                client.get(f"/api/assistant/session?report_path={rel}&session_id={sid}").get_data(as_text=True)
            )
            self.assertEqual(doc["model_branches"]["m-a"]["messages"], [])

    def test_assistant_session_get_enriches_branch_messages_with_think_split(self):
        """Branch messages must expose visible_markdown/thought_segments like top-level (dashboard loads branches)."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            rel = "branch_think.json"
            payload = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "t",
                "generated_at": "2026-01-01",
                "model_name": "mx",
                "vulnerability_name": "SQL Injection",
                "files": [],
                "stats": {"total_findings": 0},
            }
            (sec / rel).write_text(json.dumps(payload), encoding="utf-8")

            from oasis.helpers.assistant.web.persistence import new_session_id, save_chat_session

            sid = new_session_id()
            harmony_raw = (
                "<|channel>thought <channel|>Based on the report, IDOR.\n\n"
                "## Answer\n\nThe issue is valid."
            )
            save_chat_session(
                sec,
                rel,
                sid,
                [{"role": "user", "content": "q", "at": "t"}],
                "mx",
                "SQL Injection",
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/session-branch",
                data=json.dumps(
                    {
                        "report_path": rel,
                        "session_id": sid,
                        "model": "mx",
                        "messages": [
                            {"role": "user", "content": "u1", "at": "t"},
                            {"role": "assistant", "content": harmony_raw, "at": "t"},
                        ],
                        "vulnerability_name": "SQL Injection",
                        "set_as_active": True,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200)
            doc = json.loads(
                client.get(f"/api/assistant/session?report_path={rel}&session_id={sid}").get_data(as_text=True)
            )
            am = doc["model_branches"]["mx"]["messages"][1]
            self.assertEqual(am.get("role"), "assistant")
            self.assertEqual(am.get("thought_segments"), ["Based on the report, IDOR."])
            self.assertEqual(am.get("visible_markdown"), "## Answer\n\nThe issue is valid.")

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
            mock_om.get_effective_context_token_count_with_source.return_value = (None, "")
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
        mock_om.get_effective_context_token_count_with_source.return_value = (None, "")
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
            mock_om.get_effective_context_token_count_with_source.return_value = (None, "")
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
            mock_om.get_effective_context_token_count_with_source.return_value = (None, "")
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

    def test_report_json_respects_active_severity_filter_scope(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "20260101_120000" / "m1" / "json"
            run_json.mkdir(parents=True)
            low_medium = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "medium",
                "generated_at": "2026-01-01",
                "model_name": "m1",
                "vulnerability_name": "MediumOnly",
                "files": [
                    {
                        "file_path": "sample_medium.py",
                        "similarity_score": 0.7,
                        "chunk_analyses": [
                            {
                                "start_line": 1,
                                "end_line": 3,
                                "findings": [
                                    {"title": "Only Medium", "severity": "Medium", "vulnerable_code": "x"}
                                ],
                            }
                        ],
                    }
                ],
                "stats": {
                    "critical_risk": 0,
                    "high_risk": 0,
                    "medium_risk": 1,
                    "low_risk": 0,
                    "total_findings": 1,
                },
            }
            high_only = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "high",
                "generated_at": "2026-01-01",
                "model_name": "m1",
                "vulnerability_name": "HighOnly",
                "files": [
                    {
                        "file_path": "sample_high.py",
                        "similarity_score": 0.8,
                        "chunk_analyses": [
                            {
                                "start_line": 1,
                                "end_line": 3,
                                "findings": [
                                    {"title": "Only High", "severity": "High", "vulnerable_code": "x"}
                                ],
                            }
                        ],
                    }
                ],
                "stats": {
                    "critical_risk": 0,
                    "high_risk": 1,
                    "medium_risk": 0,
                    "low_risk": 0,
                    "total_findings": 1,
                },
            }
            (run_json / "medium.json").write_text(json.dumps(low_medium), encoding="utf-8")
            (run_json / "high.json").write_text(json.dumps(high_only), encoding="utf-8")

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()

            blocked = client.get("/api/report-json/20260101_120000/m1/json/medium.json?severity=high")
            self.assertEqual(blocked.status_code, 409)
            blocked_payload = json.loads(blocked.get_data(as_text=True))
            self.assertIn("active filter scope", blocked_payload.get("error", ""))

            blocked_none = client.get("/api/report-json/20260101_120000/m1/json/high.json?severity=critical")
            self.assertEqual(blocked_none.status_code, 409)
            blocked_none_payload = json.loads(blocked_none.get_data(as_text=True))
            self.assertIn("active filter scope", blocked_none_payload.get("error", ""))

            allowed = client.get("/api/report-json/20260101_120000/m1/json/high.json?severity=high")
            self.assertEqual(allowed.status_code, 200)
            allowed_payload = json.loads(allowed.get_data(as_text=True))
            self.assertEqual(allowed_payload.get("vulnerability_name"), "HighOnly")
            high_chunks = allowed_payload.get("files", [{}])[0].get("chunk_analyses", [])
            self.assertTrue(high_chunks)
            severities = [
                finding.get("severity")
                for chunk in high_chunks
                for finding in (chunk.get("findings") or [])
            ]
            self.assertEqual(severities, ["High"])

    def test_report_html_filters_non_matching_findings_by_severity(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "20260101_140000" / "m1" / "json"
            run_json.mkdir(parents=True)
            payload = {
                "report_type": "vulnerability",
                "schema_version": 5,
                "title": "Authentication Issues Security Analysis",
                "generated_at": "2026-01-01",
                "model_name": "m1",
                "vulnerability_name": "Authentication Issues",
                "vulnerability": {"name": "Authentication Issues"},
                "files": [
                    {
                        "file_path": "test_files/sample.py",
                        "similarity_score": 0.9,
                        "chunk_analyses": [
                            {
                                "start_line": 1,
                                "end_line": 5,
                                "findings": [
                                    {"title": "Critical Finding", "severity": "Critical", "vulnerable_code": "x"},
                                    {"title": "Medium Finding", "severity": "Medium", "vulnerable_code": "y"},
                                ],
                            }
                        ],
                    }
                ],
                "stats": {
                    "critical_risk": 1,
                    "high_risk": 0,
                    "medium_risk": 1,
                    "low_risk": 0,
                    "total_findings": 2,
                    "files_analyzed": 1,
                },
            }
            (run_json / "authentication_issues.json").write_text(json.dumps(payload), encoding="utf-8")

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()

            response = client.get(
                "/api/report-html?path=20260101_140000/m1/json/authentication_issues.json&severity=critical"
            )
            self.assertEqual(response.status_code, 200)
            html_payload = json.loads(response.get_data(as_text=True))
            html = html_payload.get("content", "")
            self.assertIn("Active severity filter:", html)
            self.assertIn("Critical", html)
            self.assertIn("Critical Finding", html)
            self.assertNotIn("Medium Finding", html)
            self.assertIn("report-severity-pill--critical", html)
            self.assertNotIn('class="report-header"', html)

    def test_executive_preview_meta_respects_active_severity_filter_scope(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "20260101_130000" / "m_exec" / "json"
            run_md = sec / "20260101_130000" / "m_exec" / "md"
            run_json.mkdir(parents=True)
            run_md.mkdir(parents=True)
            exec_js = {
                "report_type": "executive_summary",
                "schema_version": 1,
                "model_name": "m-exec",
                "title": "exec",
            }
            medium_only = {
                "report_type": "vulnerability",
                "schema_version": 4,
                "title": "medium",
                "generated_at": "2026-01-01",
                "model_name": "m-exec",
                "vulnerability_name": "OnlyMedium",
                "files": [{"file_path": "app.py"}],
                "stats": {
                    "critical_risk": 0,
                    "high_risk": 0,
                    "medium_risk": 2,
                    "low_risk": 0,
                    "total_findings": 2,
                },
            }
            (run_json / "_executive_summary.json").write_text(json.dumps(exec_js), encoding="utf-8")
            (run_json / "vuln_medium.json").write_text(json.dumps(medium_only), encoding="utf-8")
            (run_md / "_executive_summary.md").write_text("# Executive\n", encoding="utf-8")

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()

            blocked = client.get(
                "/api/executive-preview-meta?path=20260101_130000/m_exec/md/_executive_summary.md&severity=high"
            )
            self.assertEqual(blocked.status_code, 200)
            blocked_payload = json.loads(blocked.get_data(as_text=True))
            self.assertEqual(blocked_payload.get("vulnerability_report_files"), 0)
            self.assertEqual(blocked_payload.get("severity_counts", {}).get("high"), 0)

    def test_executive_preview_meta_tolerates_malformed_filtered_report_entries(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "20260101_150000" / "m_exec" / "json"
            run_md = sec / "20260101_150000" / "m_exec" / "md"
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
                "title": "high",
                "generated_at": "2026-01-01",
                "model_name": "m-exec",
                "vulnerability_name": "HighOnly",
                "files": [{"file_path": "app.py"}],
                "stats": {"critical_risk": 0, "high_risk": 1, "medium_risk": 0, "low_risk": 0, "total_findings": 1},
            }
            (run_json / "_executive_summary.json").write_text(json.dumps(exec_js), encoding="utf-8")
            (run_json / "vuln_high.json").write_text(json.dumps(vuln_js), encoding="utf-8")
            (run_md / "_executive_summary.md").write_text("# Executive\n", encoding="utf-8")

            original_filter_reports = server.filter_reports

            def _patched_filter_reports(**kwargs):
                rows = list(original_filter_reports(**kwargs))
                rows.append({"path": None, "format": "json", "vulnerability_type": None})
                rows.append({"path": 123, "format": "json", "vulnerability_type": 7})
                return rows

            server.filter_reports = _patched_filter_reports

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()

            resp = client.get(
                "/api/executive-preview-meta?path=20260101_150000/m_exec/md/_executive_summary.md&severity=high"
            )
            self.assertEqual(resp.status_code, 200)
            payload = json.loads(resp.get_data(as_text=True))
            self.assertEqual(payload.get("severity_counts", {}).get("high"), 1)

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
            mock_om.get_effective_context_token_count_with_source.return_value = (None, "")
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


class TestAssistantInvestigateRoute(unittest.TestCase):
    """End-to-end tests for ``POST /api/assistant/investigate``.

    Validates the bug-fix from the canonical plan: the endpoint must
    resolve ``finding_scope_report_path`` (executive aggregate flow), apply
    the post-verdict presentation filter on entry_points (FLOW + ACCESS),
    and never invent paths in the LLM narrative payload.
    """

    @staticmethod
    def _no_auth(f):
        return f

    def _make_server(self, base: Path):
        inp = base / "scan_root"
        inp.mkdir()
        report = Report(str(inp), ["json"])
        server = WebServer(report, web_password="x", web_assistant_rag=False)
        mock_om = MagicMock()
        mock_om.chat.return_value = {"message": {"content": "narrative-md"}}
        mock_om.list_chat_model_names.return_value = ["m1"]
        server._get_assistant_ollama_manager = lambda: mock_om
        return server, inp

    @staticmethod
    def _exec_payload(model: str = "m1") -> dict:
        return {
            "report_type": "executive_summary",
            "schema_version": 1,
            "model_name": model,
            "title": "Executive",
        }

    @staticmethod
    def _vuln_payload(rel_file: str, snippet_line: int, vuln: str = "Remote File Inclusion", model: str = "m1") -> dict:
        return {
            "report_type": "vulnerability",
            "schema_version": 4,
            "title": vuln,
            "generated_at": "2026-01-01",
            "model_name": model,
            "vulnerability_name": vuln,
            "files": [
                {
                    "file_path": rel_file,
                    "chunk_analyses": [
                        {
                            "start_line": snippet_line,
                            "end_line": snippet_line + 5,
                            "findings": [
                                {
                                    "title": "f",
                                    "severity": "High",
                                    "snippet_start_line": snippet_line,
                                }
                            ],
                        }
                    ],
                }
            ],
            "stats": {"total_findings": 1},
        }

    def test_investigate_resolves_sink_via_finding_scope_report_path(self):
        """Executive ``report_path`` + scope path → scope.sink_file is populated."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, scan_root = self._make_server(base)
            (scan_root / "vulnerable.sh").write_text("#!/bin/sh\n" * 130, encoding="utf-8")

            sec = base / "security_reports"
            run_json = sec / "20260101_010101" / "m1" / "json"
            run_json.mkdir(parents=True)
            (run_json / "_executive_summary.json").write_text(
                json.dumps(self._exec_payload()), encoding="utf-8"
            )
            (run_json / "remote_file_inclusion.json").write_text(
                json.dumps(self._vuln_payload("vulnerable.sh", 107)), encoding="utf-8"
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/investigate",
                data=json.dumps(
                    {
                        "report_path": "20260101_010101/m1/json/_executive_summary.json",
                        "finding_scope_report_path": "20260101_010101/m1/json/remote_file_inclusion.json",
                        "file_index": 0,
                        "chunk_index": 0,
                        "finding_index": 0,
                        "vulnerability_name": "Remote File Inclusion",
                        "synthesize_narrative": False,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
            data = json.loads(resp.get_data(as_text=True))
            scope = data.get("scope")
            self.assertIsInstance(scope, dict)
            self.assertEqual(scope.get("sink_file"), "vulnerable.sh")
            self.assertEqual(scope.get("sink_line"), 107)
            self.assertEqual(scope.get("vulnerability_name"), "Remote File Inclusion")

    def test_investigate_rejects_invalid_finding_scope_report_path(self):
        """A ``..`` traversal in finding_scope_report_path → 400."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, _ = self._make_server(base)
            sec = base / "security_reports"
            run_json = sec / "20260101_010101" / "m1" / "json"
            run_json.mkdir(parents=True)
            (run_json / "_executive_summary.json").write_text(
                json.dumps(self._exec_payload()), encoding="utf-8"
            )

            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/investigate",
                data=json.dumps(
                    {
                        "report_path": "20260101_010101/m1/json/_executive_summary.json",
                        "finding_scope_report_path": "../../escape.json",
                        "file_index": 0,
                        "chunk_index": 0,
                        "finding_index": 0,
                        "vulnerability_name": "Remote File Inclusion",
                        "synthesize_narrative": False,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)

    def test_investigate_accepts_float_sink_line_hint(self):
        """``sink_line`` provided as integral float (113.0) is accepted."""
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            server, scan_root = self._make_server(base)
            (scan_root / "app.py").write_text("a\n" * 200, encoding="utf-8")
            sec = base / "security_reports"
            run_json = sec / "20260101_010101" / "m1" / "json"
            run_json.mkdir(parents=True)
            (run_json / "vuln.json").write_text(
                json.dumps(self._vuln_payload("app.py", 50)), encoding="utf-8"
            )
            app = Flask(__name__)
            app.secret_key = "t"
            server.register_routes(app, server, self._no_auth)
            client = app.test_client()
            resp = client.post(
                "/api/assistant/investigate",
                data=json.dumps(
                    {
                        "report_path": "20260101_010101/m1/json/vuln.json",
                        "file_index": 0,
                        "chunk_index": 0,
                        "finding_index": 0,
                        "sink_file": "app.py",
                        "sink_line": 113.0,
                        "vulnerability_name": "Remote File Inclusion",
                        "synthesize_narrative": False,
                    }
                ),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 200, resp.get_data(as_text=True))
            data = json.loads(resp.get_data(as_text=True))
            self.assertEqual(data["scope"]["sink_line"], 113)


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


class TestAssistantRagRootResolution(unittest.TestCase):
    def test_resolve_assistant_cache_root_falls_back_for_stale_root(self):
        from oasis.helpers.assistant.web.rag import resolve_assistant_cache_root

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td).resolve()
            sec = td_path / "security_reports"
            sec.mkdir(parents=True, exist_ok=True)
            fallback = td_path / "fallback"
            fallback.mkdir(parents=True, exist_ok=True)
            payload = {"analysis_root": "/root/code-audit/Tchatche/Code"}
            out = resolve_assistant_cache_root(payload, sec, fallback)
            self.assertEqual(out, fallback.resolve())

    def test_resolve_assistant_cache_root_keeps_valid_local_root(self):
        from oasis.helpers.assistant.web.rag import resolve_assistant_cache_root

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td).resolve()
            sec = td_path / "security_reports"
            sec.mkdir(parents=True, exist_ok=True)
            fallback = td_path / "fallback"
            fallback.mkdir(parents=True, exist_ok=True)
            local_root = td_path / "project_root"
            local_root.mkdir(parents=True, exist_ok=True)
            payload = {"analysis_root": str(local_root)}
            out = resolve_assistant_cache_root(payload, sec, fallback)
            self.assertEqual(out, local_root.resolve())


if __name__ == "__main__":
    unittest.main()
