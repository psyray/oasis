"""Dashboard-only HTML augmentation for executive summary markdown previews."""

from __future__ import annotations

import re
from typing import List, Tuple

from bs4 import BeautifulSoup


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


def augment_executive_markdown_preview_html(inner_html: str) -> str:
    """
    Wrap executive markdown preview and inject a compact TOC with stable section anchors.

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
    nav["aria-label"] = "Executive sections"

    title = out.new_tag("h2")
    title["id"] = "table-of-contents"
    title["class"] = "report-toc-title"
    title.string = "Sections"

    ul = out.new_tag("ul")
    ul["class"] = "report-toc-list"

    for hid, label in headings:
        li = out.new_tag("li")
        a = out.new_tag("a", href=f"#{hid}")
        a["class"] = "report-toc-btn"
        span = out.new_tag("span")
        span["class"] = "report-toc-label"
        span.string = label[:120]
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

    out.append(outer)
    return str(out)
