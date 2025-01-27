import sqlite3
import logging
import base64

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