import sqlite3
import logging
import base64
import subprocess
import os
import urllib.request
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect

# SQL Injection vulnerability
def get_user(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable: Direct string concatenation
    cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
    return cursor.fetchone()

# XSS vulnerability
def render_comment(comment):
    # Vulnerable: Direct HTML rendering without escaping
    return f"<div class='comment'>{comment}</div>"

# Insufficient Input Validation
def process_age(age):
    # Vulnerable: No proper validation
    return int(age) * 12

# Sensitive Data Exposure
def save_user_data(user):
    # Vulnerable: Logging sensitive data
    logging.info(f"New user created - Username: {user['username']}, Password: {user['password']}, SSN: {user['ssn']}")

# Insecure Session Management
session_tokens = {}
def create_session(user_id):
    # Vulnerable: Predictable session token
    token = str(user_id) + "_session"
    session_tokens[user_id] = token
    return token

# Security Misconfiguration
DEBUG = True
ADMIN_PASSWORD = "admin123"  # Vulnerable: Hardcoded credentials

# Sensitive Data Logging
def log_transaction(credit_card):
    # Vulnerable: Logging sensitive data
    logging.info(f"Processing payment with card: {credit_card}")

# Insecure Cryptographic Usage
def encrypt_password(password):
    # Vulnerable: Using base64 for "encryption"
    return base64.b64encode(password.encode()).decode()

# Remote Code Execution (RCE) vulnerability
def run_command(command):
    # Vulnerable: Direct command execution
    return subprocess.check_output(command, shell=True)

def process_template(template_str, context):
    # Vulnerable: Template injection
    template_code = f"def render_template(): return f'''{template_str}'''"
    exec(template_code, context)
    return context["render_template"]()

# Server-Side Request Forgery (SSRF) vulnerability
def fetch_url(url):
    # Vulnerable: No validation of URL
    return urllib.request.urlopen(url).read()

def webhook_callback(webhook_url, data):
    # Vulnerable: No URL validation
    import requests
    return requests.post(webhook_url, json=data)

# XML External Entity (XXE) vulnerability
def parse_xml(xml_string):
    # Vulnerable: No protection against XXE
    return ET.fromstring(xml_string)

# Path Traversal vulnerability
def read_file(filename):
    # Vulnerable: No path validation
    with open(filename, 'r') as file:
        return file.read()

def save_profile_picture(user_id, filename):
    # Vulnerable: Path traversal
    path = f"uploads/{filename}"
    return path

# Insecure Direct Object Reference (IDOR) vulnerability
users_data = {
    "1": {"name": "Admin", "role": "admin", "salary": 100000},
    "2": {"name": "User", "role": "user", "salary": 50000}
}

def get_user_data(user_id):
    # Vulnerable: No access control check
    return users_data.get(user_id)

# Cross-Site Request Forgery (CSRF) vulnerability
app = Flask(__name__)

@app.route('/transfer')
def transfer_money():
    # Vulnerable: No CSRF protection
    from_account = request.args.get('from')
    to_account = request.args.get('to')
    amount = request.args.get('amount')
    # Process the transfer without CSRF token
    return f"Transferred ${amount} from {from_account} to {to_account}"

# Authentication Issues
def login(username, password):
    # Vulnerable: No rate limiting, no MFA
    if username == "admin" and password == "password":
        return True
    return False 