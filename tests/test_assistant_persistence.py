"""Tests for assistant chat session persistence helpers."""

import json
import tempfile
import unittest
from pathlib import Path

from oasis.helpers.assistant_persistence import (
    chat_dir_for_report_json,
    delete_all_chat_sessions,
    delete_chat_session,
    list_chat_sessions,
    load_chat_session,
    new_session_id,
    save_chat_session,
    validate_session_id,
)


class TestAssistantPersistence(unittest.TestCase):
    def test_new_session_id_is_uuid(self):
        sid = new_session_id()
        self.assertTrue(validate_session_id(sid))

    def test_chat_dir_next_to_report(self):
        rp = Path("/tmp/x/json/a.json")
        self.assertEqual(chat_dir_for_report_json(rp), Path("/tmp/x/json/a/chat"))

    def test_roundtrip_session(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            sec = base / "security_reports"
            sec.mkdir(parents=True)
            rel = "folder/r.json"
            rp = sec / rel
            rp.parent.mkdir(parents=True)
            rp.write_text(
                json.dumps(
                    {
                        "schema_version": 4,
                        "model_name": "m",
                        "vulnerability_name": "XSS",
                        "files": [],
                        "stats": {},
                    }
                ),
                encoding="utf-8",
            )

            sid = new_session_id()
            messages = [
                {"role": "user", "content": "hello", "at": "2026-01-01T00:00:00Z"},
                {"role": "assistant", "content": "hi", "at": "2026-01-01T00:00:01Z"},
            ]
            save_chat_session(sec, rel, sid, messages, "m", "XSS")

            listing = list_chat_sessions(sec, rel)
            self.assertEqual(len(listing), 1)
            self.assertEqual(listing[0]["session_id"], sid)

            doc = load_chat_session(sec, rel, sid)
            assert doc is not None
            self.assertEqual(doc["messages"], messages)
            self.assertEqual(doc["session_id"], sid)

            self.assertTrue(delete_chat_session(sec, rel, sid))
            self.assertIsNone(load_chat_session(sec, rel, sid))

    def test_delete_all(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            sec = base / "security_reports"
            sec.mkdir(parents=True)
            rel = "z.json"
            rp = sec / rel
            rp.write_text(json.dumps({"schema_version": 4, "files": [], "stats": {}}), encoding="utf-8")

            sid = new_session_id()
            save_chat_session(sec, rel, sid, [{"role": "user", "content": "a", "at": "2026-01-01T00:00:00Z"}], "m", "")
            n = delete_all_chat_sessions(sec, rel)
            self.assertEqual(n, 1)
            self.assertEqual(list_chat_sessions(sec, rel), [])


if __name__ == "__main__":
    unittest.main()
