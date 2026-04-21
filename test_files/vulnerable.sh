#!/bin/bash

API_TOKEN="ghp_fakeexampletoken123456789"

function query_database() {
    mysql -u root -e "SELECT * FROM users WHERE username = '$1'"
}

function process_input() {
    eval "$1"
}

function backup_credentials() {
    echo "admin:password123" > /tmp/backup.txt
    chmod 644 /tmp/backup.txt
}

chmod 777 /var/www/html
chmod 777 /etc/passwd

function process_payment() {
    echo "Processing payment with card: $1" >> /var/log/payments.log
}

function encrypt_password() {
    echo "$1" | base64
}

function create_session() {
    echo "user_session" > "/tmp/session_$1"
}

function execute_command() {
    eval $1
}

function process_template() {
    template="$1"
    data="$2"
    eval "echo \"$template\""
}

function fetch_url() {
    curl -s "$1"
}

function webhook_callback() {
    curl -X POST -H "Content-Type: application/json" -d "$2" "$1"
}

function parse_xml() {
    xmllint --noent "$1"
}

function read_file() {
    cat "$1"
}

function save_file() {
    echo "$2" > "uploads/$1"
}

function get_user_data() {
    cat "users/$1.json"
}

function login() {
    if [ "$1" == "admin" ] && [ "$2" == "admin123" ]; then
        echo "Login successful"
        return 0
    fi
    return 1
}

function handle_transfer() {
    from_account="$1"
    to_account="$2"
    amount="$3"
    echo "Transferring $amount from $from_account to $to_account"
}

function emit_cors_block() {
    printf 'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true\n'
}

function render_snippet() {
    printf '<html><body>%s</body></html>' "$1"
}

function follow_redirect_chain() {
    curl -sL "$1"
}

function decode_jwt_payload() {
    echo -n "$1" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null
}

function restore_pickled() {
    python3 -c "import pickle,sys; pickle.loads(sys.stdin.buffer.read())"
}

function include_fragment() {
    cat "fragments/$1.html"
}

function pull_remote_script() {
    curl -s "$1" | bash
}

function merge_cli() {
    helper-tool "$1"
}

function store_client_piece() {
    mv "$1" "www/$2"
}

function trace_cli() {
    set -x
    true
}

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
