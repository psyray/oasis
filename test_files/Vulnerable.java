import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Base64;
import java.util.logging.Logger;
import java.io.*;
import java.net.URL;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.DocumentBuilder;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class Vulnerable {
    private static final Logger LOGGER = Logger.getLogger(Vulnerable.class.getName());
    
    // SQL Injection vulnerability
    public void getUserData(String username) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "");
            Statement stmt = conn.createStatement();
            // Vulnerable: Direct string concatenation
            stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        } catch (Exception e) {
            LOGGER.severe("Database error: " + e.getMessage());
        }
    }

    // XSS vulnerability
    public String displayUserInput(String input) {
        // Vulnerable: Direct HTML output
        return "<div class='user-content'>" + input + "</div>";
    }

    // Insufficient Input Validation
    public int calculateUserAge(String age) {
        // Vulnerable: No validation
        return Integer.parseInt(age) * 12;
    }

    // Sensitive Data Exposure
    public void saveUserCredentials(String username, String password) {
        // Vulnerable: Logging sensitive data
        LOGGER.info("New user - Username: " + username + ", Password: " + password);
    }

    // Session Management Issues
    private static java.util.Map<String, String> sessions = new java.util.HashMap<>();
    public String createSession(String userId) {
        // Vulnerable: Predictable session token
        String token = userId + System.currentTimeMillis();
        sessions.put(userId, token);
        return token;
    }

    // Security Misconfiguration
    private static final String ADMIN_PASSWORD = "admin123";  // Vulnerable: Hardcoded credential
    private static final boolean DEBUG_MODE = true;  // Vulnerable: Debug enabled in production

    // Sensitive Data Logging
    public void processPayment(String creditCard) {
        // Vulnerable: Logging sensitive data
        LOGGER.info("Processing payment with card: " + creditCard);
    }

    // Insecure Cryptographic Usage
    public String encryptPassword(String password) {
        // Vulnerable: Using base64 as "encryption"
        return Base64.getEncoder().encodeToString(password.getBytes());
    }

    // Remote Code Execution (RCE) vulnerability
    public Object executeCode(String code) throws Exception {
        // Vulnerable: Dynamic code execution
        return Class.forName("javax.script.ScriptEngineManager")
                .newInstance()
                .getClass()
                .getMethod("getEngineByName", String.class)
                .invoke(Class.forName("javax.script.ScriptEngineManager").newInstance(), "js")
                .getClass()
                .getMethod("eval", String.class)
                .invoke(Class.forName("javax.script.ScriptEngineManager")
                        .newInstance()
                        .getClass()
                        .getMethod("getEngineByName", String.class)
                        .invoke(Class.forName("javax.script.ScriptEngineManager").newInstance(), "js"), code);
    }
    
    public Process runCommand(String command) throws Exception {
        // Vulnerable: Direct command execution
        return Runtime.getRuntime().exec(command);
    }
    
    // Server-Side Request Forgery (SSRF) vulnerability
    public String fetchUrl(String url) throws Exception {
        // Vulnerable: No URL validation
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(new URL(url).openStream())
        );
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }
    
    // XML External Entity (XXE) vulnerability
    public Document parseXml(String xml) throws Exception {
        // Vulnerable: No protection against XXE
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xml)));
    }
    
    // Path Traversal vulnerability
    public String readFile(String fileName) throws Exception {
        // Vulnerable: No path validation
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }
    
    // Insecure Direct Object Reference (IDOR) vulnerability
    private String[] userRecords = {"admin:secret", "user:password"};
    
    public String getUserRecord(int id) {
        // Vulnerable: No access control
        return userRecords[id];
    }
    
    // Authentication Issues
    public boolean login(String username, String password) {
        // Vulnerable: Weak authentication
        if (username.equals("admin") && password.equals("admin123")) {
            return true;
        }
        return false;
    }
    
    // Cross-Site Request Forgery (CSRF) vulnerability
    public boolean transferMoney(String fromAccount, String toAccount, int amount) {
        // Vulnerable: No CSRF protection
        LOGGER.info("Transferring " + amount + " from " + fromAccount + " to " + toAccount);
        // Process transfer without validating request origin
        return true;
    }
} 