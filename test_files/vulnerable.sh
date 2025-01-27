#!/bin/bash

# SQL Injection vulnerability
function query_database() {
    # Vulnerable: Direct variable interpolation
    mysql -u root -e "SELECT * FROM users WHERE username = '$1'"
}

# Insufficient Input Validation
function process_input() {
    # Vulnerable: No input validation
    eval "$1"  # Executing user input directly
}

# Sensitive Data Exposure
function backup_credentials() {
    # Vulnerable: Storing sensitive data in plain text
    echo "admin:password123" > /tmp/backup.txt
    chmod 644 /tmp/backup.txt
}

# Security Misconfiguration
# Vulnerable: Weak permissions
chmod 777 /var/www/html
chmod 777 /etc/passwd

# Sensitive Data Logging
function process_payment() {
    # Vulnerable: Logging sensitive data
    echo "Processing payment with card: $1" >> /var/log/payments.log
}

# Insecure Cryptographic Usage
function encrypt_password() {
    # Vulnerable: Using weak encryption
    echo "$1" | base64
}

# Session Management Issues
function create_session() {
    # Vulnerable: Predictable session file
    echo "user_session" > "/tmp/session_$1"
}

# Example usage
query_database "user' OR '1'='1"
process_input "rm -rf /"
backup_credentials
process_payment "4111-1111-1111-1111"
encrypt_password "secret123"
create_session "admin" 