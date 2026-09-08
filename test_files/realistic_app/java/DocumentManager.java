/*
Realistic vulnerable fixture: a minimal Java document-management API.

Static test file for OASIS. Contains dangerous sinks on purpose.
No Spring context, no real DB, no external services.
*/

package com.oasis.fixture;

import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.regex.Pattern;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.InputSource;

public class DocumentManager {

    private static final String ADMIN_PASSWORD = "admin123";
    private static final String DB_URL = "jdbc:postgresql://db.internal:5432/appdb";

    // ---------------------------------------------------------------------------
    // SQL injection
    // ---------------------------------------------------------------------------

    public String searchDocumentsVulnerable(String title) throws SQLException {
        // VULNERABLE: concatenation.
        Connection conn = DriverManager.getConnection(DB_URL, "appuser", "SuperSecret123");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM docs WHERE title = '" + title + "'");
        StringBuilder sb = new StringBuilder();
        while (rs.next()) sb.append(rs.getString(1)).append("\n");
        return sb.toString();
    }

    public String searchDocumentsSafe(String title) throws SQLException {
        // SAFE: parameterized.
        Connection conn = DriverManager.getConnection(DB_URL, "appuser", "SuperSecret123");
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM docs WHERE title = ?");
        ps.setString(1, title);
        ResultSet rs = ps.executeQuery();
        StringBuilder sb = new StringBuilder();
        while (rs.next()) sb.append(rs.getString(1)).append("\n");
        return sb.toString();
    }

    public String getDocumentByIdVulnerable(int id) throws SQLException {
        // VULNERABLE: integer concatenated.
        Connection conn = DriverManager.getConnection(DB_URL, "appuser", "SuperSecret123");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM docs WHERE id = " + id);
        return rs.next() ? rs.getString(1) : null;
    }

    // ---------------------------------------------------------------------------
    // Command injection
    // ---------------------------------------------------------------------------

    public String pingHostVulnerable(String host) throws IOException, InterruptedException {
        // VULNERABLE: shell command with user input.
        Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ping -c 1 " + host});
        return readProcessOutput(p);
    }

    private static final Pattern HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.\\-]{1,253}$");

    public String pingHostSafe(String host) throws IOException, InterruptedException {
        // SAFE: allowlist + no shell.
        if (!HOST_PATTERN.matcher(host).matches()) return "invalid host";
        Process p = new ProcessBuilder("ping", "-c", "1", host).start();
        return readProcessOutput(p);
    }

    private String readProcessOutput(Process p) throws IOException, InterruptedException {
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) sb.append(line).append("\n");
        p.waitFor();
        return sb.toString();
    }

    // ---------------------------------------------------------------------------
    // XSS
    // ---------------------------------------------------------------------------

    public String renderDocumentVulnerable(int id) {
        // VULNERABLE: unescaped HTML.
        Document doc = loadDocument(id);
        return "<h1>" + doc.title + "</h1><p>" + doc.body + "</p>";
    }

    public String renderDocumentSafe(int id) {
        // SAFE: escaped.
        Document doc = loadDocument(id);
        return "<h1>" + escapeHtml(doc.title) + "</h1><p>" + escapeHtml(doc.body) + "</p>";
    }

    private String escapeHtml(String text) {
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&#x27;");
    }

    // ---------------------------------------------------------------------------
    // Path traversal / LFI
    // ---------------------------------------------------------------------------

    public String readAttachmentVulnerable(String filename) throws IOException {
        // VULNERABLE: user path joined directly.
        Path path = Paths.get("attachments", filename);
        return Files.readString(path);
    }

    public String readAttachmentSafe(String filename) throws IOException {
        // PARTIALLY SAFE: basename + realpath check.
        String safe = Paths.get(filename).getFileName().toString();
        Path base = Paths.get("attachments").toAbsolutePath().normalize();
        Path target = base.resolve(safe).toAbsolutePath().normalize();
        if (!target.startsWith(base)) return "invalid path";
        return Files.readString(target);
    }

    // ---------------------------------------------------------------------------
    // SSRF + open redirect
    // ---------------------------------------------------------------------------

    public String fetchUrlVulnerable(String url) throws IOException {
        // VULNERABLE: arbitrary URL.
        URL u = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
            return sb.toString();
        }
    }

    public String fetchUrlSafe(String url) throws IOException {
        // SAFE: host allowlist.
        URL u = new URL(url);
        String host = u.getHost();
        if (!host.equals("api.example.com") && !host.equals("status.example.com")) {
            return "host not allowed";
        }
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
            return sb.toString();
        }
    }

    public String redirectTargetVulnerable(String next) {
        // VULNERABLE: open redirect.
        return next;
    }

    public String redirectTargetSafe(String next) {
        // SAFE: allowlist.
        if (!next.equals("/dashboard") && !next.equals("/docs") && !next.equals("/logout")) {
            next = "/";
        }
        return next;
    }

    // ---------------------------------------------------------------------------
    // Weak crypto / hardcoded secret
    // ---------------------------------------------------------------------------

    public String hashPasswordVulnerable(String password) throws Exception {
        // VULNERABLE: MD5.
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public String loginVulnerable(String username, String password) {
        // VULNERABLE: hardcoded backdoor.
        if ("admin".equals(username) && ADMIN_PASSWORD.equals(password)) {
            return "admin_session";
        }
        return null;
    }

    // ---------------------------------------------------------------------------
    // XXE
    // ---------------------------------------------------------------------------

    public String parseXmlVulnerable(String xml) throws Exception {
        // VULNERABLE: external entities enabled.
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xml)));
        return doc.getDocumentElement().getTagName();
    }

    public String parseXmlSafe(String xml) throws Exception {
        // SAFE: entities disabled.
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(xml)));
        return doc.getDocumentElement().getTagName();
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private Document loadDocument(int id) {
        return new Document("Doc " + id, "Body with <script>alert(1)</script>");
    }

    record Document(String title, String body) {}

    public static void main(String[] args) {
        // Static fixture: no runtime server.
    }
}
