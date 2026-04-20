"""Normalize report preview HTML so links work when embedded on the dashboard (any base URL)."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote

from bs4 import BeautifulSoup

_FMT_SEGMENTS = frozenset({"pdf", "json", "md", "html", "sarif"})
_SKIP_HREF_PREFIXES = ("#", "mailto:", "javascript:", "data:", "vbscript:")
_EXTERNAL_PREFIXES = ("http://", "https://")


def _relative_to_security(candidate: Path, security_root: Path) -> Path | None:
    try:
        return candidate.resolve().relative_to(security_root.resolve())
    except ValueError:
        return None


def _reports_href_from_relative_file(rel: Path) -> str:
    return f"/reports/{rel.as_posix()}"


def _skip_rewrite_href(href: str) -> bool:
    """Leave fragments, schemes, absolute /reports/, and external URLs unchanged."""
    return (
        not href
        or href.startswith(_SKIP_HREF_PREFIXES)
        or href.startswith("/reports/")
        or href.startswith(_EXTERNAL_PREFIXES)
    )


def _rewrite_mangled_root_absolute_href(
    href: str,
    model_dir: Path,
    security_root: Path,
) -> str | None:
    """Repair ``/pdf/...`` etc. resolved against ``/dashboard`` instead of the report tree."""
    if not href.startswith("/") or href.startswith("//"):
        return None
    path_unquoted = Path(unquote(href.lstrip("/")))
    parts = path_unquoted.parts
    if len(parts) < 1 or str(parts[0]).lower() not in _FMT_SEGMENTS:
        return None
    fmt_folder = str(parts[0]).lower()
    tail = Path(*parts[1:]) if len(parts) > 1 else Path()
    if not tail.name:
        return None
    candidate = model_dir / fmt_folder / tail.name
    rel = _relative_to_security(candidate, security_root)
    return _reports_href_from_relative_file(rel) if rel is not None else None


def _rewrite_relative_report_href(
    href: str,
    md_parent: Path,
    security_root: Path,
) -> str | None:
    """Resolve normal relative links (e.g. ``../pdf/x.pdf``) under ``security_root``."""
    try:
        joined = (md_parent / href).resolve()
    except OSError:
        return None
    rel = _relative_to_security(joined, security_root)
    return _reports_href_from_relative_file(rel) if rel is not None else None


def rewrite_report_preview_anchor_hrefs(html: str, markdown_file: Path, security_root: Path) -> str:
    """
    Rewrite anchor ``href`` values so they use ``/reports/<path-under-security-root>``.

    Markdown ``../pdf/x.pdf`` resolves incorrectly when the preview fragment is injected on
    ``/dashboard`` (browser base URL), producing ``/pdf/x.pdf``. Relative paths are
    resolved against the markdown file directory; leading ``/pdf/`` mangled paths are
    repaired using the markdown file's model directory (parent of ``md/``).
    """
    if not (html or "").strip():
        return html

    root = security_root.resolve()
    md_path = markdown_file.resolve()
    md_parent = md_path.parent
    model_dir = md_parent.parent

    soup = BeautifulSoup(html, "html.parser")
    for link in soup.find_all("a", href=True):
        raw = link.get("href")
        if raw is None:
            continue
        href = str(raw).strip()
        if _skip_rewrite_href(href):
            continue

        new_href = _rewrite_mangled_root_absolute_href(href, model_dir, root)
        if new_href is None:
            new_href = _rewrite_relative_report_href(href, md_parent, root)

        if new_href is not None:
            link["href"] = new_href

    return str(soup)
