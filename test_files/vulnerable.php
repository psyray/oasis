<?php
// SQL Injection vulnerability
function getUserData($username) {
    $conn = new mysqli("localhost", "root", "", "users");
    // Vulnerable: Direct variable interpolation
    $query = "SELECT * FROM users WHERE username = '$username'";
    return $conn->query($query);
}

// XSS vulnerability
function displayUserInput($message) {
    // Vulnerable: Direct output without escaping
    echo "<div class='message'>$message</div>";
}

// Insufficient Input Validation
function processUserAge($age) {
    // Vulnerable: No validation
    return $age * 12;
}

// Sensitive Data Exposure
function saveUserCredentials($username, $password) {
    // Vulnerable: Storing plain text password
    file_put_contents('credentials.txt', "$username:$password\n", FILE_APPEND);
}

// Session Management Issues
function createUserSession($userId) {
    // Vulnerable: Weak session management
    session_start();
    $_SESSION['user'] = $userId;
    // No session regeneration, no secure flags
}

// Security Misconfiguration
ini_set('display_errors', 1);  // Vulnerable: Exposing errors
error_reporting(E_ALL);

// Sensitive Data Logging
function logPayment($creditCard) {
    // Vulnerable: Logging sensitive data
    error_log("Processing payment for card: $creditCard");
}

// Insecure Cryptographic Usage
function encryptPassword($password) {
    // Vulnerable: Using weak hashing
    return md5($password);
}

// Remote Code Execution (RCE) vulnerability
function runCommand($cmd) {
    // Vulnerable: Direct command execution
    return shell_exec($cmd);
}

function evaluateCode($code) {
    // Vulnerable: Direct eval of user input
    return eval($code);
}

// Server-Side Request Forgery (SSRF) vulnerability
function fetchExternalResource($url) {
    // Vulnerable: No URL validation
    return file_get_contents($url);
}

// XML External Entity (XXE) vulnerability
function parseXmlDocument($xml) {
    // Vulnerable: No protection against XXE
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT);
    return $doc;
}

// Path Traversal vulnerability
function getFileContents($fileName) {
    // Vulnerable: No path validation
    return file_get_contents($fileName);
}

function saveUploadedFile($fileName) {
    // Vulnerable: Path traversal
    $filePath = "uploads/" . $fileName;
    return $filePath;
}

// Insecure Direct Object Reference (IDOR) vulnerability
function getUserProfile($userId) {
    // Vulnerable: No access control checks
    $filePath = "users/" . $userId . ".json";
    return json_decode(file_get_contents($filePath), true);
}

// Authentication Issues
function loginUser($username, $password) {
    // Vulnerable: Weak password policy, no MFA
    $users = [
        "admin" => "password123",
        "user" => "123456"
    ];
    
    return isset($users[$username]) && $users[$username] === $password;
}

// Cross-Site Request Forgery (CSRF) vulnerability
function processMoneyTransfer($fromAccount, $toAccount, $amount) {
    // Vulnerable: No CSRF token validation
    // Just process the transfer based on parameters
    return "Transferred $amount from $fromAccount to $toAccount";
}

?> 