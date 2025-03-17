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

# Remote Code Execution (RCE) vulnerability
function execute_command() {
    # Vulnerable: Direct command execution
    eval $1
}

function process_template() {
    # Vulnerable: Template injection through eval
    template="$1"
    data="$2"
    eval "echo \"$template\""
}

# Server-Side Request Forgery (SSRF) vulnerability
function fetch_url() {
    # Vulnerable: No URL validation
    curl -s "$1"
}

function webhook_callback() {
    # Vulnerable: No URL validation
    curl -X POST -H "Content-Type: application/json" -d "$2" "$1"
}

# XML External Entity (XXE) vulnerability - shell script example
function parse_xml() {
    # Vulnerable: Using external entity processing
    xmllint --noent "$1"
}

# Path Traversal vulnerability
function read_file() {
    # Vulnerable: No path validation
    cat "$1"
}

function save_file() {
    # Vulnerable: Path traversal
    echo "$2" > "uploads/$1"
}

# Insecure Direct Object Reference (IDOR) vulnerability
function get_user_data() {
    # Vulnerable: Direct reference to objects without access control
    cat "users/$1.json"
}

# Authentication Issues
function login() {
    # Vulnerable: Weak authentication, hardcoded credentials
    if [ "$1" == "admin" ] && [ "$2" == "admin123" ]; then
        echo "Login successful"
        return 0
    fi
    return 1
}

# Cross-Site Request Forgery (CSRF) vulnerability - shell script server example
function handle_transfer() {
    # Vulnerable: No CSRF protection
    from_account="$1"
    to_account="$2"
    amount="$3"
    echo "Transferring $amount from $from_account to $to_account"
    # Process transfer without validating request origin
}

# Example usage
query_database "user' OR '1'='1"
process_input "rm -rf /"
backup_credentials
process_payment "4111-1111-1111-1111"
encrypt_password "secret123"
create_session "admin"
execute_command "cat /etc/passwd"
fetch_url "http://internal-server/admin"
read_file "../../../etc/passwd"
handle_transfer "account1" "hacker_account" "1000" 