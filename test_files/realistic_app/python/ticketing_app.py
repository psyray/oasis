"""
Realistic vulnerable fixture: a minimal Flask help-desk / ticketing API.

This is a static test file used by OASIS to validate data-flow aware findings.
It is NOT meant to be run as a service: it contains dangerous sinks on purpose.

Design rules:
- One coherent scenario (ticket search, admin diagnostics, document upload).
- Vulnerable and safe variants live side-by-side so OASIS can test precision.
- No external dependencies (SQLite, subprocess, filesystem only).
- Entry point -> sink in at most 3 hops.
"""

import base64
import os
import re
import sqlite3
import subprocess  # nosec: intentional command injection sink for tests
from html import escape

from flask import Flask, jsonify, redirect, request

app = Flask(__name__)
app.config["DEBUG"] = True


# ---------------------------------------------------------------------------
# Data helpers (no real DB needed for static analysis)
# ---------------------------------------------------------------------------
def _db_connection():
    return sqlite3.connect("tickets.db")


def _load_ticket(ticket_id):
    return {"id": ticket_id, "title": "Sample ticket", "body": "Sample body"}


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

@app.route("/ticket/search")
def search_ticket():
    """VULNERABLE: user input concatenated into raw SQL."""
    title = request.args.get("title", "")
    conn = _db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tickets WHERE title = '" + title + "'")
    return jsonify(cur.fetchall())


@app.route("/ticket/search-safe")
def search_ticket_safe():
    """SAFE: parameterized query."""
    title = request.args.get("title", "")
    conn = _db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tickets WHERE title = ?", (title,))
    return jsonify(cur.fetchall())


@app.route("/ticket/<ticket_id>")
def get_ticket(ticket_id):
    """VULNERABLE: raw SQL built from path parameter."""
    conn = _db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM tickets WHERE id = " + ticket_id)
    return jsonify(cur.fetchone())


# ---------------------------------------------------------------------------
# Command injection
# ---------------------------------------------------------------------------

@app.route("/admin/ping")
def admin_ping():
    """VULNERABLE: shell command built from query parameter."""
    host = request.args.get("host", "")
    output = subprocess.check_output("ping -c 1 " + host, shell=True, text=True)
    return jsonify({"output": output})


@app.route("/admin/ping-safe")
def admin_ping_safe():
    """SAFE: strict allowlist + no shell."""
    host = request.args.get("host", "")
    if not re.match(r"^[a-zA-Z0-9\.\-]{1,253}$", host):
        return jsonify({"error": "invalid host"}), 400
    output = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True
    ).stdout
    return jsonify({"output": output})


@app.route("/admin/diag")
def admin_diag():
    """VULNERABLE: command injection through a hidden action parameter."""
    action = request.args.get("action", "")
    return subprocess.check_output(action, shell=True, text=True)


# ---------------------------------------------------------------------------
# Cross-site scripting (stored / reflected)
# ---------------------------------------------------------------------------

@app.route("/ticket/<ticket_id>/render")
def render_ticket(ticket_id):
    """VULNERABLE: unsanitized user content reflected in HTML."""
    ticket = _load_ticket(ticket_id)
    return f"<h1>{ticket['title']}</h1><p>{ticket['body']}</p>"


@app.route("/ticket/<ticket_id>/render-safe")
def render_ticket_safe(ticket_id):
    """SAFE: HTML-escaped output."""
    ticket = _load_ticket(ticket_id)
    return f"<h1>{escape(ticket['title'])}</h1><p>{escape(ticket['body'])}</p>"


@app.route("/feedback")
def feedback():
    """VULNERABLE: reflected XSS from query string."""
    message = request.args.get("msg", "")
    return f"<div class='feedback'>Thank you for: {message}</div>"


# ---------------------------------------------------------------------------
# Insecure deserialization
# ---------------------------------------------------------------------------

@app.route("/internal/import", methods=["POST"])
def import_backup():
    """VULNERABLE: pickle.loads on attacker-controlled data."""
    import pickle  # nosec: test fixture — imported locally to keep the dangerous sink visible
    data = base64.b64decode(request.data)
    obj = pickle.loads(data)  # nosec: test fixture
    return jsonify(obj)


@app.route("/internal/import-json", methods=["POST"])
def import_backup_json():
    """SAFE: JSON-only import."""
    import json

    payload = request.get_json(force=True)
    return jsonify({"imported": payload})


# ---------------------------------------------------------------------------
# Path traversal / LFI
# ---------------------------------------------------------------------------

@app.route("/docs/<path:filename>")
def read_doc(filename):
    """VULNERABLE: path traversal via user path."""
    with open(os.path.join("docs", filename)) as f:
        return f.read()


@app.route("/docs-safe/<path:filename>")
def read_doc_safe(filename):
    """PARTIALLY SAFE: basename only, but extension not restricted."""
    safe_name = os.path.basename(filename)
    base_dir = os.path.abspath("docs")
    target = os.path.abspath(os.path.join(base_dir, safe_name))
    if not target.startswith(base_dir + os.sep):
        return jsonify({"error": "invalid path"}), 400
    with open(target) as f:
        return f.read()


# ---------------------------------------------------------------------------
# Server-side request forgery + open redirect
# ---------------------------------------------------------------------------

@app.route("/fetch")
def fetch_url():
    """VULNERABLE: SSRF through user-supplied URL."""
    import urllib.request  # local import keeps fixture self-contained

    url = request.args.get("url", "")
    with urllib.request.urlopen(url) as response:  # nosec: test fixture
        return response.read()


@app.route("/fetch-safe")
def fetch_url_safe():
    """SAFE: allowlist of allowed downstream hosts."""
    import urllib.request

    allowed_hosts = {"api.example.com", "status.example.com"}
    url = request.args.get("url", "")
    parsed = __import__("urllib.parse").parse.urlparse(url)
    if parsed.hostname not in allowed_hosts:
        return jsonify({"error": "host not allowed"}), 400
    with urllib.request.urlopen(url) as response:
        return response.read()


@app.route("/goto")
def goto():
    """VULNERABLE: open redirect."""
    next_url = request.args.get("next", "/")
    return redirect(next_url)


@app.route("/goto-safe")
def goto_safe():
    """SAFE: allowlist redirect targets."""
    allowed = {"/dashboard", "/tickets", "/logout"}
    next_url = request.args.get("next", "/")
    if next_url not in allowed:
        next_url = "/"
    return redirect(next_url)


# ---------------------------------------------------------------------------
# Weak cryptography / secrets in code
# ---------------------------------------------------------------------------

ADMIN_PASSWORD = "admin123"  # nosec: hardcoded secret fixture
DATABASE_URL = "postgresql://appuser:SuperSecret123@db.internal:5432/appdb"  # nosec


def hash_password(password):
    """VULNERABLE: MD5 password hashing."""
    import hashlib

    return hashlib.md5(password.encode()).hexdigest()  # nosec: test fixture


def encrypt_token(token):
    """VULNERABLE: base64 is not encryption."""
    return base64.b64encode(token.encode()).decode()


@app.route("/login")
def login():
    """VULNERABLE: hardcoded admin backdoor."""
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    if username == "admin" and password == ADMIN_PASSWORD:
        return jsonify({"token": encrypt_token("admin_session")})
    return jsonify({"error": "unauthorized"}), 401


# ---------------------------------------------------------------------------
# XML external entity (XXE)
# ---------------------------------------------------------------------------

@app.route("/xml/parse", methods=["POST"])
def parse_xml():
    """VULNERABLE: XXE via external resolver."""
    from xml.dom.minidom import parseString

    xml_data = request.data.decode("utf-8")
    doc = parseString(xml_data)
    return jsonify({"root": doc.documentElement.tagName})


@app.route("/xml/parse-safe", methods=["POST"])
def parse_xml_safe():
    """SAFE: disabled external entities / DTD."""
    from defusedxml import ElementTree as ET

    xml_data = request.data.decode("utf-8")
    root = ET.fromstring(xml_data)
    return jsonify({"root": root.tag})


if __name__ == "__main__":
    app.run(debug=True)
