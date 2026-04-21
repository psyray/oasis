"""
GitHub release metadata and optional CLI self-update for OASIS (no PyPI).

Stable releases only: GitHub entries with draft or prerelease set are ignored.
"""

from __future__ import annotations

import importlib.metadata
import json
import logging
import os
import shutil
import subprocess
import sys
import sysconfig
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

GITHUB_OWNER = "psyray"
GITHUB_REPO = "oasis"
RELEASES_API_URL = f"https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases"
GIT_REMOTE_INSTALL_URL = "https://github.com/psyray/oasis.git"

CACHE_SUBDIR = "oasis"
CACHE_FILENAME = "update_check.json"
CACHE_TTL_SECONDS = 24 * 3600

ENV_DISABLE_CHECK = "OASIS_NO_UPDATE_CHECK"
ENV_DEBUG_UPDATE_BANNER = "OASIS_DEBUG_UPDATE"


@dataclass(frozen=True)
class StableRelease:
    """Latest non-draft, non-prerelease GitHub release."""

    tag_name: str
    version: Version
    published_at: str


def _user_agent() -> str:
    try:
        ver = installed_version_string()
    except Exception:
        ver = "unknown"
    return f"oasis/{ver} (+https://github.com/{GITHUB_OWNER}/{GITHUB_REPO})"


def installed_version_string() -> str:
    """Installed distribution version (metadata) or embedded ``__version__``."""
    try:
        return importlib.metadata.version("oasis")
    except importlib.metadata.PackageNotFoundError:
        from oasis import __version__

        return str(__version__)


def version_from_tag_name(tag_name: str) -> Optional[Version]:
    """Parse a PEP 440 version from a release tag (leading ``v`` stripped when typical)."""
    raw = (tag_name or "").strip()
    if not raw:
        return None
    if len(raw) > 1 and raw[0].lower() == "v" and raw[1].isdigit():
        raw = raw[1:]
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _iter_site_package_roots() -> list[Path]:
    """Return candidate site-packages root directories as resolved Paths."""
    roots: set[Path] = set()

    try:
        cfg_paths = sysconfig.get_paths()
        for key in ("purelib", "platlib"):
            p = cfg_paths.get(key)
            if p:
                roots.add(Path(p))
    except (KeyError, TypeError, OSError):
        pass

    try:
        import site

        gs = getattr(site, "getsitepackages", None)
        if callable(gs):
            for p in gs() or []:
                roots.add(Path(p))
        gu = getattr(site, "getusersitepackages", None)
        if callable(gu):
            user_site = gu()
            if user_site:
                roots.add(Path(user_site))
    except Exception:
        pass

    for entry in sys.path:
        if not entry:
            continue
        p = Path(entry)
        name = p.name.lower()
        if "site-packages" in name or "dist-packages" in name:
            roots.add(p)

    normalized: list[Path] = []
    for r in roots:
        try:
            normalized.append(r.resolve())
        except OSError:
            normalized.append(r)
    return normalized


def _is_under_any(path: Path, roots: list[Path]) -> bool:
    """Return True if ``path`` is located under any of the given ``roots``."""
    try:
        path = path.resolve()
    except OSError:
        pass

    for root in roots:
        try:
            root_resolved = root.resolve()
        except OSError:
            root_resolved = root

        try:
            path.relative_to(root_resolved)
            return True
        except ValueError:
            continue
    return False


def is_site_packages_install() -> bool:
    """True when ``oasis`` is loaded from a recognized site-packages root (sysconfig/site/sys.path)."""
    import oasis

    pkg_paths = getattr(oasis, "__path__", None)
    pkg_path: Path
    if pkg_paths:
        try:
            pkg_path = Path(next(iter(pkg_paths)))
        except StopIteration:
            src = getattr(oasis, "__file__", None)
            if not src:
                return False
            pkg_path = Path(src)
    else:
        src = getattr(oasis, "__file__", None)
        if not src:
            return False
        pkg_path = Path(src)

    roots = _iter_site_package_roots()
    return _is_under_any(pkg_path, roots)


def _cache_base_dir() -> Path:
    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg) / CACHE_SUBDIR
    return Path.home() / ".cache" / CACHE_SUBDIR


def cache_file_path() -> Path:
    return _cache_base_dir() / CACHE_FILENAME


def _read_cache() -> Optional[dict[str, Any]]:
    path = cache_file_path()
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _write_cache(payload: dict[str, Any]) -> None:
    path = cache_file_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    except OSError as exc:
        logger.debug("Failed to write CLI update cache at %s: %s", path, exc)


def pick_latest_stable_release(releases: list[dict[str, Any]]) -> Optional[StableRelease]:
    """
    Choose the newest stable release by ``published_at`` (ISO-8601), excluding draft/prerelease.
    """
    candidates: list[tuple[str, StableRelease]] = []
    for rel in releases:
        if not isinstance(rel, dict):
            continue
        if rel.get("draft"):
            continue
        if rel.get("prerelease"):
            continue
        tag = rel.get("tag_name")
        if not tag or not isinstance(tag, str):
            continue
        pub = rel.get("published_at")
        if not pub or not isinstance(pub, str):
            continue
        ver = version_from_tag_name(tag)
        if ver is None:
            continue
        candidates.append(
            (pub, StableRelease(tag_name=tag, version=ver, published_at=pub))
        )
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1]


def fetch_latest_stable_release(
    *,
    client: Optional[httpx.Client] = None,
    timeout_sec: float = 12.0,
) -> Optional[StableRelease]:
    """
    GET GitHub releases (first page), return newest stable release or None on failure/empty.
    """
    owns_client = client is None
    if client is None:
        client = httpx.Client(timeout=timeout_sec, follow_redirects=True)
    try:
        headers = {"Accept": "application/vnd.github+json", "User-Agent": _user_agent()}
        response = client.get(RELEASES_API_URL, params={"per_page": 100}, headers=headers)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            return None
        return pick_latest_stable_release(data)
    except (httpx.HTTPError, ValueError, TypeError):
        return None
    finally:
        if owns_client:
            client.close()


def resolve_latest_stable_for_notice(
    *,
    force_refresh: bool,
    client: Optional[httpx.Client] = None,
) -> tuple[Optional[StableRelease], bool]:
    """
    Return (release, used_network). Uses disk cache when fresh unless force_refresh.
    """
    now = time.time()
    cached = None if force_refresh else _read_cache()
    if cached:
        try:
            ts = float(cached.get("checked_at_epoch", 0))
            tag = cached.get("tag_name")
            ver_s = cached.get("latest_version")
            if tag and ver_s and (now - ts) <= CACHE_TTL_SECONDS:
                ver = Version(ver_s)
                pub = str(cached.get("published_at", ""))
                return StableRelease(tag_name=str(tag), version=ver, published_at=pub), False
        except (InvalidVersion, TypeError, ValueError):
            pass

    latest = fetch_latest_stable_release(client=client)
    if latest is not None:
        _write_cache(
            {
                "checked_at_epoch": now,
                "tag_name": latest.tag_name,
                "latest_version": str(latest.version),
                "published_at": latest.published_at,
            }
        )
    return latest, True


def _log_update_banner_error(exc: BaseException) -> None:
    """Best-effort logging of unexpected errors during update-banner emission."""
    raw = os.environ.get(ENV_DEBUG_UPDATE_BANNER, "")
    debug = raw.lower() in {"1", "true", "yes"}
    if not debug:
        return
    print(
        f"oasis: update-banner error: {type(exc).__name__}: {exc}",
        file=sys.stderr,
    )


def maybe_emit_update_banner(*, silent: bool) -> None:
    """Non-fatal stderr one-liner when a newer stable release exists."""
    if silent:
        return
    if os.environ.get(ENV_DISABLE_CHECK):
        return
    try:
        local = Version(installed_version_string())
        latest, _ = resolve_latest_stable_for_notice(force_refresh=False)
        if latest is None or latest.version <= local:
            return
        pip_ref = f"git+{GIT_REMOTE_INSTALL_URL}@{latest.tag_name}"
        print(
            f"oasis: update available ({local} -> {latest.version}). "
            f"Run: pipx install --force {pip_ref}",
            file=sys.stderr,
        )
    except (InvalidVersion, ValueError, OSError, TypeError, httpx.HTTPError):
        return
    except Exception as exc:
        _log_update_banner_error(exc)


def print_check_update() -> int:
    """Print local vs latest stable from GitHub; stdout user text, non-zero on hard errors."""
    try:
        local_v = Version(installed_version_string())
    except InvalidVersion:
        print("Could not parse installed version.", file=sys.stderr)
        return 1

    latest = fetch_latest_stable_release()
    if latest is None:
        print(
            "Could not determine the latest stable release (network or GitHub API).",
            file=sys.stderr,
        )
        return 1

    print(f"Current version: {local_v}")
    print(f"Latest stable:   {latest.version} ({latest.tag_name})")

    if latest.version > local_v:
        pip_ref = f"git+{GIT_REMOTE_INSTALL_URL}@{latest.tag_name}"
        print("Update available. Run: oasis --self-update")
        print(f"Or: pipx install --force {pip_ref}")
        return 0

    print("Up to date.")
    return 0


def run_self_update() -> int:
    """Install the latest stable tag via pipx (``git+https``), if available."""
    if not is_site_packages_install():
        print(
            "This install is not a normal site-packages install (likely editable/dev). "
            "Update from your Git clone with: git pull",
            file=sys.stderr,
        )
        return 1

    try:
        local_v = Version(installed_version_string())
    except InvalidVersion:
        print("Could not parse installed version.", file=sys.stderr)
        return 1

    latest = fetch_latest_stable_release()
    if latest is None:
        print(
            "Could not determine the latest stable release (network or GitHub API).",
            file=sys.stderr,
        )
        return 1

    if latest.version <= local_v:
        print(f"Already up to date ({local_v}).")
        return 0

    pip_url = f"git+{GIT_REMOTE_INSTALL_URL}@{latest.tag_name}"

    pipx_exe = shutil.which("pipx")
    if pipx_exe is None:
        print(
            "pipx not found on PATH. Install pipx or run manually:\n"
            f"  pip install --upgrade \"oasis @ {pip_url}\"",
            file=sys.stderr,
        )
        return 1

    cmd = [pipx_exe, "install", "--force", pip_url]
    print(f"Upgrading to {latest.tag_name} ({latest.version}) …")
    proc = subprocess.run(cmd)
    return int(proc.returncode)

