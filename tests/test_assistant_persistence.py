"""Tests for assistant chat session persistence helpers."""

import json
import tempfile
import unittest
from pathlib import Path

from oasis.helpers.assistant.web.persistence import (
    CHAT_SCHEMA_VERSION,
    branch_key,
    chat_dir_for_report_json,
    delete_all_chat_sessions,
    delete_chat_session,
    ensure_session_views,
    finding_validation_storage_key,
    get_finding_validation_for_branch,
    list_chat_sessions,
    load_chat_session,
    merge_finding_validation_into_session,
    new_session_id,
    save_chat_session,
    save_session_branch_messages,
    validate_session_id,
)


class TestAssistantPersistence(unittest.TestCase):
    def test_new_session_id_is_uuid(self):
        sid = new_session_id()
        self.assertTrue(validate_session_id(sid))

    def test_chat_dir_next_to_report(self):
        rp = Path("/tmp/x/json/a.json")
        self.assertEqual(chat_dir_for_report_json(rp), Path("/tmp/x/json/a/chat"))

    def test_branch_key_trims(self):
        self.assertEqual(branch_key("  m  "), "m")

    def test_roundtrip_session_v2(self):
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
            self.assertEqual(doc["schema_version"], CHAT_SCHEMA_VERSION)
            self.assertEqual(doc["messages"], messages)
            self.assertIn("model_branches", doc)
            self.assertIn("m", doc["model_branches"])
            self.assertEqual(doc["model_branches"]["m"]["messages"], messages)
            self.assertEqual(doc["model_branches"]["m"].get("finding_validations"), {})

            self.assertTrue(delete_chat_session(sec, rel, sid))
            self.assertIsNone(load_chat_session(sec, rel, sid))

    def test_two_models_preserve_validation_on_other_branch(self):
        with tempfile.TemporaryDirectory() as td:
            sec = Path(td) / "security_reports"
            sec.mkdir(parents=True)
            rel = "a.json"
            rp = sec / rel
            rp.write_text(
                json.dumps({"schema_version": 4, "vulnerability_name": "XSS", "files": [], "stats": {}}),
                encoding="utf-8",
            )
            sid = new_session_id()
            fk0 = finding_validation_storage_key("", 0, 0, 0)
            assert fk0 is not None
            save_chat_session(sec, rel, sid, [{"role": "user", "content": "a", "at": "t"}], "alpha", "XSS")
            merge_finding_validation_into_session(
                sec,
                rel,
                sid,
                "alpha",
                {"status": "confirmed_exploitable", "vulnerability_name": "XSS", "family": "flow"},
                "XSS",
                finding_key=fk0,
            )
            save_chat_session(
                sec,
                rel,
                sid,
                [{"role": "user", "content": "b", "at": "t"}],
                "beta",
                "XSS",
            )
            doc = load_chat_session(sec, rel, sid)
            assert doc is not None
            fv_a = doc["model_branches"]["alpha"]["finding_validations"].get(fk0)
            self.assertIsInstance(fv_a, dict)
            self.assertEqual(fv_a.get("status"), "confirmed_exploitable")
            self.assertEqual(doc["model_branches"]["beta"].get("finding_validations"), {})

    def test_two_finding_keys_preserved_on_same_branch(self):
        with tempfile.TemporaryDirectory() as td:
            sec = Path(td) / "security_reports"
            sec.mkdir(parents=True)
            rel = "twok.json"
            (sec / rel).write_text(
                json.dumps({"schema_version": 4, "vulnerability_name": "XSS", "files": [], "stats": {}}),
                encoding="utf-8",
            )
            sid = new_session_id()
            fk0 = finding_validation_storage_key("", 0, 0, 0)
            fk1 = finding_validation_storage_key("", 0, 0, 1)
            assert fk0 is not None and fk1 is not None and fk0 != fk1
            merge_finding_validation_into_session(
                sec,
                rel,
                sid,
                "alpha",
                {"status": "confirmed_exploitable", "vulnerability_name": "XSS"},
                "XSS",
                finding_key=fk0,
            )
            merge_finding_validation_into_session(
                sec,
                rel,
                sid,
                "alpha",
                {"status": "likely_exploitable", "vulnerability_name": "XSS"},
                "XSS",
                finding_key=fk1,
            )
            doc = load_chat_session(sec, rel, sid)
            assert doc is not None
            fvs = doc["model_branches"]["alpha"]["finding_validations"]
            self.assertEqual(fvs[fk0].get("status"), "confirmed_exploitable")
            self.assertEqual(fvs[fk1].get("status"), "likely_exploitable")

    def test_merge_finding_validation_creates_file(self):
        with tempfile.TemporaryDirectory() as td:
            sec = Path(td) / "security_reports"
            sec.mkdir(parents=True)
            rel = "b.json"
            (sec / rel).write_text(
                json.dumps({"schema_version": 4, "vulnerability_name": "Y", "files": [], "stats": {}}),
                encoding="utf-8",
            )
            sid = new_session_id()
            fk0 = finding_validation_storage_key("", 0, 0, 0)
            assert fk0 is not None
            merge_finding_validation_into_session(
                sec,
                rel,
                sid,
                "m1",
                {"status": "likely_exploitable", "vulnerability_name": "Y", "family": "access"},
                "Y",
                finding_key=fk0,
            )
            doc = load_chat_session(sec, rel, sid)
            assert doc is not None
            self.assertEqual(doc["schema_version"], CHAT_SCHEMA_VERSION)
            fv = get_finding_validation_for_branch(doc, "m1", fk0)
            self.assertIsNotNone(fv)
            assert fv is not None
            self.assertEqual(fv.get("status"), "likely_exploitable")

    def test_save_session_branch_set_as_active(self):
        with tempfile.TemporaryDirectory() as td:
            sec = Path(td) / "security_reports"
            sec.mkdir(parents=True)
            rel = "c.json"
            (sec / rel).write_text(
                json.dumps({"schema_version": 4, "vulnerability_name": "Z", "files": [], "stats": {}}),
                encoding="utf-8",
            )
            sid = new_session_id()
            save_chat_session(sec, rel, sid, [{"role": "user", "content": "a1", "at": "t"}], "alpha", "Z")
            save_session_branch_messages(
                sec,
                rel,
                sid,
                "beta",
                [{"role": "user", "content": "b1", "at": "t"}],
                "Z",
                set_as_active=True,
            )
            doc = ensure_session_views(load_chat_session(sec, rel, sid) or {})
            self.assertEqual(doc.get("model"), "beta")
            self.assertEqual(len(doc.get("messages") or []), 1)
            self.assertEqual(doc["messages"][0].get("content"), "b1")

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
