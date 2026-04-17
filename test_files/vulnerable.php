<?php

function getUserData($username) {
    $conn = new mysqli("localhost", "root", "", "users");

    $query = "SELECT * FROM users WHERE username = '$username'";
    return $conn->query($query);
}

function displayUserInput($message) {
    echo "<div class='message'>$message</div>";
}

function processUserAge($age) {
    return $age * 12;
}

function saveUserCredentials($username, $password) {
    file_put_contents('credentials.txt', "$username:$password\n", FILE_APPEND);
}

function createUserSession($userId) {
    session_start();
    $_SESSION['user'] = $userId;
}

ini_set('display_errors', 1);
error_reporting(E_ALL);

function logPayment($creditCard) {
    error_log("Processing payment for card: $creditCard");
}

function encryptPassword($password) {
    return md5($password);
}

function runCommand($cmd) {
    return shell_exec($cmd);
}

function evaluateCode($code) {
    return eval($code);
}

function fetchExternalResource($url) {
    return file_get_contents($url);
}

function parseXmlDocument($xml) {
    $doc = new DOMDocument();
    $doc->loadXML($xml, LIBXML_NOENT);
    return $doc;
}

function getFileContents($fileName) {
    return file_get_contents($fileName);
}

function saveUploadedFile($fileName) {
    $filePath = "uploads/" . $fileName;
    return $filePath;
}

function getUserProfile($userId) {
    $filePath = "users/" . $userId . ".json";
    return json_decode(file_get_contents($filePath), true);
}

function loginUser($username, $password) {
    $users = [
        "admin" => "password123",
        "user" => "123456"
    ];

    return isset($users[$username]) && $users[$username] === $password;
}

function processMoneyTransfer($fromAccount, $toAccount, $amount) {
    return "Transferred $amount from $fromAccount to $toAccount";
}

const STRIPE_SECRET = "stripe_secret_example_do_not_use";

function emit_cors_bundle() {
    header("Access-Control-Allow-Origin: *");
    header("Access-Control-Allow-Credentials: true");
}

function follow_return_url() {
    header('Location: ' . $_GET['returnUrl']);
}

function load_sidebar($slug) {
    include "partials/" . $slug . ".php";
}

function load_remote_template($url) {
    include $url;
}

function accept_blob($raw) {
    return unserialize($raw);
}

function move_client_upload($tmp, $orig) {
    move_uploaded_file($tmp, "public/" . $orig);
}

function jwt_segment_two($token) {
    $p = explode('.', $token);
    $b = strtr($p[1], '-_', '+/');
    $pad = strlen($b) % 4;
    if ($pad) {
        $b .= str_repeat('=', 4 - $pad);
    }
    return base64_decode($b);
}

function echo_stack(Throwable $e) {
    echo $e->getTraceAsString();
}

function merge_flags($userInput) {
    shell_exec("helper " . $userInput);
}

?>
