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
?> 