<?php
/*
Realistic vulnerable fixture: a minimal PHP blog / admin panel.

Static test file for OASIS. Contains dangerous sinks on purpose.
*/

// ---------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------

function search_posts_vulnerable($mysqli) {
    // VULNERABLE: raw concatenation.
    $title = $_GET['title'] ?? '';
    $query = "SELECT * FROM posts WHERE title = '$title'";
    return $mysqli->query($query);
}

function search_posts_safe($mysqli) {
    // SAFE: parameterized.
    $title = $_GET['title'] ?? '';
    $stmt = $mysqli->prepare("SELECT * FROM posts WHERE title = ?");
    $stmt->bind_param("s", $title);
    $stmt->execute();
    return $stmt->get_result();
}

function get_post_vulnerable($mysqli, $id) {
    // VULNERABLE: integer concatenated.
    return $mysqli->query("SELECT * FROM posts WHERE id = $id");
}

// ---------------------------------------------------------------------------
// Command injection
// ---------------------------------------------------------------------------

function admin_ping_vulnerable() {
    // VULNERABLE: shell_exec with user input.
    $host = $_GET['host'] ?? '';
    return shell_exec("ping -c 1 $host");
}

function admin_ping_safe() {
    // SAFE: allowlist + no shell.
    $host = $_GET['host'] ?? '';
    if (!preg_match('/^[a-zA-Z0-9\.\-]{1,253}$/', $host)) {
        return "invalid host";
    }
    return shell_exec("ping -c 1 " . escapeshellarg($host));
}

// ---------------------------------------------------------------------------
// XSS
// ---------------------------------------------------------------------------

function render_comment_vulnerable($comment) {
    // VULNERABLE: reflected without escaping.
    return "<div class='comment'>$comment</div>";
}

function render_comment_safe($comment) {
    // SAFE: escaped.
    return "<div class='comment'>" . htmlspecialchars($comment, ENT_QUOTES, 'UTF-8') . "</div>";
}

function feedback_vulnerable() {
    // VULNERABLE: reflected XSS.
    $msg = $_GET['msg'] ?? '';
    return "<div class='feedback'>Thank you for: $msg</div>";
}

// ---------------------------------------------------------------------------
// LFI / path traversal
// ---------------------------------------------------------------------------

function read_doc_vulnerable($page) {
    // VULNERABLE: user path read directly.
    return file_get_contents("docs/$page");
}

function read_doc_safe($page) {
    // PARTIALLY SAFE: basename only.
    $safe = basename($page);
    $baseDir = realpath('docs');
    $target = realpath("$baseDir/$safe");
    if ($target === false || strpos($target, $baseDir) !== 0) {
        return "invalid path";
    }
    return file_get_contents($target);
}

// ---------------------------------------------------------------------------
// SSRF + open redirect
// ---------------------------------------------------------------------------

function fetch_url_vulnerable() {
    // VULNERABLE: arbitrary URL fetch.
    $url = $_GET['url'] ?? '';
    return file_get_contents($url);
}

function fetch_url_safe() {
    // SAFE: host allowlist.
    $allowed = ['api.example.com', 'status.example.com'];
    $url = $_GET['url'] ?? '';
    $host = parse_url($url, PHP_URL_HOST);
    if (!in_array($host, $allowed, true)) {
        return "host not allowed";
    }
    return file_get_contents($url);
}

function redirect_vulnerable() {
    // VULNERABLE: open redirect.
    $next = $_GET['next'] ?? '/';
    header("Location: $next");
    exit;
}

function redirect_safe() {
    // SAFE: path allowlist.
    $allowed = ['/dashboard', '/posts', '/logout'];
    $next = $_GET['next'] ?? '/';
    if (!in_array($next, $allowed, true)) {
        $next = '/';
    }
    header("Location: $next");
    exit;
}

// ---------------------------------------------------------------------------
// Weak crypto / hardcoded secret
// ---------------------------------------------------------------------------

$ADMIN_PASSWORD = "admin123";
$DB_PASSWORD = "SuperSecret123";

function hash_password_vulnerable($password) {
    // VULNERABLE: MD5.
    return md5($password);
}

function login_vulnerable($username, $password) {
    // VULNERABLE: hardcoded backdoor.
    global $ADMIN_PASSWORD;
    if ($username === 'admin' && $password === $ADMIN_PASSWORD) {
        return "admin_token";
    }
    return null;
}

// ---------------------------------------------------------------------------
// XXE
// ---------------------------------------------------------------------------

function parse_xml_vulnerable($xml) {
    // VULNERABLE: external entities.
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT);
    return $doc->documentElement->tagName;
}

function parse_xml_safe($xml) {
    // SAFE: entities disabled.
    $doc = new DOMDocument();
    $previous = libxml_disable_entity_loader(true);
    $doc->loadXML($xml, LIBXML_NONET);
    libxml_disable_entity_loader($previous);
    return $doc->documentElement->tagName;
}

// ---------------------------------------------------------------------------
// Main router (kept procedural for readability)
// ---------------------------------------------------------------------------

$mysqli = new mysqli("localhost", "root", "", "blog");

$action = $_GET['action'] ?? '';
switch ($action) {
    case 'search':
        echo search_posts_vulnerable($mysqli);
        break;
    case 'search_safe':
        echo search_posts_safe($mysqli);
        break;
    case 'post':
        echo get_post_vulnerable($mysqli, $_GET['id'] ?? 0);
        break;
    case 'ping':
        echo admin_ping_vulnerable();
        break;
    case 'ping_safe':
        echo admin_ping_safe();
        break;
    case 'feedback':
        echo feedback_vulnerable();
        break;
    case 'read':
        echo read_doc_vulnerable($_GET['page'] ?? '');
        break;
    case 'read_safe':
        echo read_doc_safe($_GET['page'] ?? '');
        break;
    case 'fetch':
        echo fetch_url_vulnerable();
        break;
    case 'fetch_safe':
        echo fetch_url_safe();
        break;
    case 'redirect':
        redirect_vulnerable();
        break;
    case 'redirect_safe':
        redirect_safe();
        break;
    case 'xml':
        echo parse_xml_vulnerable(file_get_contents('php://input'));
        break;
    case 'xml_safe':
        echo parse_xml_safe(file_get_contents('php://input'));
        break;
    case 'login':
        echo login_vulnerable($_GET['username'] ?? '', $_GET['password'] ?? '');
        break;
    default:
        echo render_comment_vulnerable($_GET['comment'] ?? '');
        break;
}
