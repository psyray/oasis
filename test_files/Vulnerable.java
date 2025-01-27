import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Base64;
import java.util.logging.Logger;

public class Vulnerable {
    private static final Logger LOGGER = Logger.getLogger(Vulnerable.class.getName());
    
    // SQL Injection vulnerability
    public void getUserData(String username) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
            Statement stmt = conn.createStatement();
            // Vulnerable: String concatenation in SQL
            stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // XSS vulnerability
    public String displayUserInput(String input) {
        // Vulnerable: Direct HTML output
        return "<div class='user-content'>" + input + "</div>";
    }

    // Insufficient Input Validation
    public int processAge(String age) {
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
} 