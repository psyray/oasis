"""Dashboard-only HTML augmentation for executive summary markdown previews."""

from __future__ import annotations

import re
from typing import List, Tuple, Union

from bs4 import BeautifulSoup
from bs4.element import Tag


def _toc_icon_for_heading(label: str) -> str:
    """Emoji for TOC row, aligned with vulnerability report TOC affordances."""
    s = label.strip().lower()
    if any(k in s for k in ("overview", "executive summary")) or s == "summary":
        return "📋"
    if "model" in s:
        return "🤖"
    if any(k in s for k in ("statistics", "stats", "severity", "rollup", "distribution")):
        return "📊"
    if any(k in s for k in ("file", "similarity", "cluster", "group")):
        return "📁"
    if any(k in s for k in ("analysis", "detail", "finding")):
        return "🔍"
    if "vulnerab" in s:
        return "🛡️"
    if any(k in s for k in ("error", "note", "warning")):
        return "⚠️"
    if any(k in s for k in ("progress", "scan", "embed")):
        return "⏱️"
    if any(k in s for k in ("assistant", "triage")):
        return "💬"
    return "📄"


def _slug_anchor_id(text: str, used: set[str]) -> str:
    """Build a stable HTML id from heading text (ASCII slug, collision-safe)."""
    raw = text.strip().lower()
    raw = re.sub(r"[^a-z0-9]+", "-", raw)
    raw = raw.strip("-") or "section"
    base = raw[:80]
    candidate = base
    n = 2
    while candidate in used:
        candidate = f"{base}-{n}"
        n += 1
    used.add(candidate)
    return candidate


def _is_nav_table_of_contents_heading(tag: Tag) -> bool:
    if tag.name not in ("h2", "h3"):
        return False
    if tag.get("id") == "table-of-contents":
        return True
    nav = tag.find_parent("nav")
    if nav is None:
        return False
    classes = nav.get("class") or []
    return "report-toc" in classes


def _make_return_to_toc_paragraph(soup: BeautifulSoup) -> Tag:
    """Same markup as ``_macros.html.j2`` ``render_return_to_toc``."""
    p = soup.new_tag("p", attrs={"class": "report-return-top"})
    a = soup.new_tag(
        "a",
        attrs={
            "class": "report-return-top-link",
            "href": "#table-of-contents",
        },
    )
    a.string = "Return to table of contents"
    p.append(a)
    return p


def _insert_return_to_toc_links(soup: BeautifulSoup, outer: Tag) -> None:
    """Insert a return link after each content section (mirrors vulnerability report UX).

    Multiple headings can share the same structural boundary (e.g. several ``h3`` siblings
    before the next ``h2``); ``insert_before`` on that boundary must run only once so we do
    not stack duplicate paragraphs (seen under Scan Progress / Pipeline phases).
    """
    headings: List[Tag] = []
    for tag in outer.find_all(["h2", "h3"], recursive=True):
        if _is_nav_table_of_contents_heading(tag):
            continue
        headings.append(tag)

    used_boundary_ids: set[int] = set()
    appended_final_return = False

    for i, h in enumerate(headings):
        lvl = int(h.name[1])
        boundary: Union[Tag, None] = None
        for j in range(i + 1, len(headings)):
            nh = headings[j]
            if lvl == 2:
                if nh.name == "h2":
                    boundary = nh
                    break
            else:
                boundary = nh
                break
        para = _make_return_to_toc_paragraph(soup)
        if boundary is not None:
            bid = id(boundary)
            if bid in used_boundary_ids:
                continue
            used_boundary_ids.add(bid)
            boundary.insert_before(para)
        else:
            if appended_final_return:
                continue
            appended_final_return = True
            outer.append(para)


def augment_executive_markdown_preview_html(inner_html: str) -> str:
    """
    Wrap executive markdown preview and inject a compact TOC with stable section anchors,
    plus ``report-return-top`` links after each section (same pattern as vulnerability HTML).

    Reuses vulnerability preview CSS classes (``report-toc``, ``report-toc-btn``, …).
    """
    if not inner_html or not inner_html.strip():
        return inner_html

    frag = BeautifulSoup(inner_html, "html.parser")
    container = frag.body if frag.body is not None else frag

    used_ids: set[str] = {"table-of-contents"}
    headings: List[Tuple[str, str]] = []

    for tag in container.find_all(["h2", "h3"]):
        txt = tag.get_text(strip=True)
        if not txt:
            continue
        hid = tag.get("id")
        if not hid or not str(hid).strip():
            hid = _slug_anchor_id(txt, used_ids)
            tag["id"] = hid
        else:
            used_ids.add(str(hid).strip())
        headings.append((str(tag["id"]), txt))
        if len(headings) >= 24:
            break

    out = BeautifulSoup("", "html.parser")
    outer = out.new_tag("div")
    outer["class"] = "executive-preview html-content-container"

    nav = out.new_tag("nav")
    nav["class"] = "report-toc executive-preview-toc"
    nav["aria-label"] = "Table of contents"

    title = out.new_tag("h2")
    title["id"] = "table-of-contents"
    title["class"] = "report-toc-title"
    title.string = "Table of contents"

    ul = out.new_tag("ul")
    ul["class"] = "report-toc-list"

    for hid, label in headings:
        li = out.new_tag("li")
        a = out.new_tag("a", href=f"#{hid}")
        a["class"] = "report-toc-btn"
        icon = out.new_tag("span")
        icon["class"] = "report-toc-icon"
        icon["aria-hidden"] = "true"
        icon.string = _toc_icon_for_heading(label)
        span = out.new_tag("span")
        span["class"] = "report-toc-label"
        span.string = label[:120]
        a.append(icon)
        a.append(span)
        li.append(a)
        ul.append(li)

    nav.append(title)
    nav.append(ul)
    outer.append(nav)

    if frag.body is not None:
        for child in list(frag.body.children):
            if getattr(child, "name", None) or str(child).strip():
                outer.append(child)
    else:
        for child in list(frag.children):
            if getattr(child, "name", None) or str(child).strip():
                outer.append(child)

    _insert_return_to_toc_links(out, outer)

    out.append(outer)
    return str(out)
