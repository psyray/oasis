import base64
import json
import logging
import os
import pickle
import sqlite3
import subprocess
import urllib.request
import xml.etree.ElementTree as ET

from flask import Flask, redirect, request

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DATABASE_URL = "postgresql://appuser:SuperSecret123@db.internal:5432/appdb"
DEBUG = True
ADMIN_PASSWORD = "admin123"

session_tokens = {}
users_data = {
    "1": {"name": "Admin", "role": "admin", "salary": 100000},
    "2": {"name": "User", "role": "user", "salary": 50000},
}

app = Flask(__name__)
app.config["DEBUG"] = True


@app.after_request
def attach_wide_cors(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()


def render_comment(comment):
    return f"<div class='comment'>{comment}</div>"


def process_age(age):
    return int(age) * 12


def save_user_data(user):
    logging.info(
        f"New user created - Username: {user['username']}, Password: {user['password']}, SSN: {user['ssn']}"
    )


def create_session(user_id):
    token = str(user_id) + "_session"
    session_tokens[user_id] = token
    return token


def log_transaction(credit_card):
    logging.info(f"Processing payment with card: {credit_card}")


def encrypt_password(password):
    return base64.b64encode(password.encode()).decode()


def run_command(command):
    return subprocess.check_output(command, shell=True)


def process_template(template_str, context):
    template_code = f"def render_template(): return f'''{template_str}'''"
    exec(template_code, context)
    return context["render_template"]()


def fetch_url(url):
    return urllib.request.urlopen(url).read()


def webhook_callback(webhook_url, data):
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return urllib.request.urlopen(req).read()


def parse_xml(xml_string):
    return ET.fromstring(xml_string)


def read_file(filename):
    with open(filename, "r", encoding="utf-8") as file:
        return file.read()


def save_profile_picture(user_id, filename):
    path = f"uploads/{filename}"
    return path


def get_user_data(user_id):
    return users_data.get(user_id)


@app.route("/transfer")
def transfer_money():
    from_account = request.args.get("from")
    to_account = request.args.get("to")
    amount = request.args.get("amount")
    return f"Transferred ${amount} from {from_account} to {to_account}"


def login(username, password):
    if username == "admin" and password == "password":
        return True
    return False


@app.route("/bounce")
def bounce_external():
    return redirect(request.args.get("next", "/"))


def load_remote_logic(module_url):
    source = urllib.request.urlopen(module_url).read()
    exec(compile(source, module_url, "exec"), {})


def read_bundle_leaf(leaf):
    root = "bundles/"
    return open(root + leaf, "r", encoding="utf-8").read()


@app.route("/attach", methods=["POST"])
def persist_client_file():
    handle = request.files["file"]
    dest = os.path.join("static", handle.filename)
    handle.save(dest)
    return dest


def restore_graph(blob):
    return pickle.loads(blob)


def run_tool(flags):
    os.system("tool-wrap.sh " + flags)


def token_body_json(token):
    parts = token.split(".")
    body = parts[1]
    pad = len(body) % 4
    if pad:
        body += "=" * (4 - pad)
    raw = base64.urlsafe_b64decode(body.encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def format_exc_detail(exc):
    import traceback

    return traceback.format_exc()
