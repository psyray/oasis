"""Unit tests for GitHub-based CLI update helpers."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from packaging.version import Version

from oasis.helpers import cli_update


class TestVersionFromTag(unittest.TestCase):
    def test_strips_leading_v(self):
        self.assertEqual(cli_update.version_from_tag_name("v1.2.3"), Version("1.2.3"))

    def test_invalid_returns_none(self):
        self.assertIsNone(cli_update.version_from_tag_name("not-a-version"))


class TestPickLatestStableRelease(unittest.TestCase):
    def test_skips_prerelease_and_draft(self):
        releases = [
            {
                "tag_name": "v2.0.0-beta",
                "published_at": "2025-03-01T00:00:00Z",
                "draft": False,
                "prerelease": True,
            },
            {
                "tag_name": "v1.0.0",
                "published_at": "2025-01-01T00:00:00Z",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v9.9.9",
                "published_at": "2026-06-01T00:00:00Z",
                "draft": True,
                "prerelease": False,
            },
        ]
        picked = cli_update.pick_latest_stable_release(releases)
        self.assertIsNotNone(picked)
        assert picked is not None
        self.assertEqual(str(picked.version), "1.0.0")
        self.assertEqual(picked.tag_name, "v1.0.0")

    def test_newest_by_published_at(self):
        releases = [
            {
                "tag_name": "v1.0.0",
                "published_at": "2025-01-01T00:00:00Z",
                "draft": False,
                "prerelease": False,
            },
            {
                "tag_name": "v1.1.0",
                "published_at": "2025-06-01T00:00:00Z",
                "draft": False,
                "prerelease": False,
            },
        ]
        picked = cli_update.pick_latest_stable_release(releases)
        self.assertIsNotNone(picked)
        assert picked is not None
        self.assertEqual(str(picked.version), "1.1.0")


class TestPrintCheckUpdate(unittest.TestCase):
    def test_github_unreachable_returns_one(self):
        with patch.object(cli_update, "fetch_latest_stable_release", return_value=None):
            rc = cli_update.print_check_update()
        self.assertEqual(rc, 1)

    def test_up_to_date_zero(self):
        fake = cli_update.StableRelease(
            tag_name="v99.99.99",
            version=Version("99.99.99"),
            published_at="2026-01-01T00:00:00Z",
        )
        with patch.object(cli_update, "fetch_latest_stable_release", return_value=fake):
            with patch.object(cli_update, "installed_version_string", return_value="99.99.99"):
                rc = cli_update.print_check_update()
        self.assertEqual(rc, 0)


class TestRunSelfUpdate(unittest.TestCase):
    def test_editable_returns_one(self):
        with patch.object(cli_update, "is_site_packages_install", return_value=False):
            rc = cli_update.run_self_update()
        self.assertEqual(rc, 1)

    def test_up_to_date_skips_pipx(self):
        fake = cli_update.StableRelease(
            tag_name="v0.0.1",
            version=Version("0.0.1"),
            published_at="2020-01-01T00:00:00Z",
        )
        with patch.object(cli_update, "is_site_packages_install", return_value=True):
            with patch.object(cli_update, "fetch_latest_stable_release", return_value=fake):
                with patch.object(cli_update, "installed_version_string", return_value="1.0.0"):
                    with patch.object(cli_update.subprocess, "run") as run:
                        rc = cli_update.run_self_update()
        run.assert_not_called()
        self.assertEqual(rc, 0)

    def test_upgrade_invokes_pipx(self):
        fake = cli_update.StableRelease(
            tag_name="v2.0.0",
            version=Version("2.0.0"),
            published_at="2026-01-01T00:00:00Z",
        )
        proc = MagicMock()
        proc.returncode = 0
        with patch.object(cli_update, "is_site_packages_install", return_value=True):
            with patch.object(cli_update, "fetch_latest_stable_release", return_value=fake):
                with patch.object(cli_update, "installed_version_string", return_value="1.0.0"):
                    with patch.object(cli_update.shutil, "which", return_value="/usr/bin/pipx"):
                        with patch.object(cli_update.subprocess, "run", return_value=proc) as run:
                            rc = cli_update.run_self_update()
        self.assertEqual(rc, 0)
        args = run.call_args[0][0]
        self.assertEqual(
            args[:4],
            ["/usr/bin/pipx", "install", "--force", "git+https://github.com/psyray/oasis.git@v2.0.0"],
        )


class TestMaybeEmitBanner(unittest.TestCase):
    def test_respects_silent(self):
        with patch.object(cli_update, "resolve_latest_stable_for_notice") as res:
            cli_update.maybe_emit_update_banner(silent=True)
        res.assert_not_called()

    def test_respects_env(self):
        with patch.dict(os.environ, {cli_update.ENV_DISABLE_CHECK: "1"}, clear=False):
            with patch.object(cli_update, "resolve_latest_stable_for_notice") as res:
                cli_update.maybe_emit_update_banner(silent=False)
        res.assert_not_called()


class TestCacheRoundTrip(unittest.TestCase):
    def test_cache_refresh_writes_file(self):
        fake = cli_update.StableRelease(
            tag_name="v1.2.3",
            version=Version("1.2.3"),
            published_at="2026-02-01T00:00:00Z",
        )
        with tempfile.TemporaryDirectory() as td:
            base = Path(td) / "cache"
            with patch.dict(os.environ, {"XDG_CACHE_HOME": str(base)}, clear=False):
                with patch.object(cli_update, "fetch_latest_stable_release", return_value=fake):
                    rel, net = cli_update.resolve_latest_stable_for_notice(force_refresh=True)
                self.assertTrue(net)
                self.assertIsNotNone(rel)
                path = cli_update.cache_file_path()
                self.assertTrue(path.is_file())
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(data["tag_name"], "v1.2.3")


class TestOasisCliUpdateFlags(unittest.TestCase):
    def test_parse_check_and_self_exclusive(self):
        from oasis.oasis import OasisScanner

        scanner = OasisScanner()
        parser = scanner.setup_argument_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--check-update", "--self-update"])
        self.assertEqual(ctx.exception.code, 2)
        td = tempfile.mkdtemp()
        try:
            ns = parser.parse_args(["-i", td, "--check-update"])
            self.assertTrue(ns.check_update)
            self.assertFalse(ns.self_update)
        finally:
            Path(td).rmdir()

