import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.StringReader;
import java.net.URL;
import java.net.URLClassLoader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class Vulnerable {
    private static final Logger LOGGER = Logger.getLogger(Vulnerable.class.getName());
    private static final String ADMIN_PASSWORD = "admin123";
    private static final boolean DEBUG_MODE = true;
    private static final String AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
    private static final Map<String, String> sessions = new HashMap<>();
    private final String[] userRecords = {"admin:secret", "user:password"};

    public void getUserData(String username) {
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "root", "");
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
        } catch (Exception e) {
            LOGGER.severe("Database error: " + e.getMessage());
        }
    }

    public String displayUserInput(String input) {
        return "<div class='user-content'>" + input + "</div>";
    }

    public int calculateUserAge(String age) {
        return Integer.parseInt(age) * 12;
    }

    public void saveUserCredentials(String username, String password) {
        LOGGER.info("New user - Username: " + username + ", Password: " + password);
    }

    public String createSession(String userId) {
        String token = userId + System.currentTimeMillis();
        sessions.put(userId, token);
        return token;
    }

    public void processPayment(String creditCard) {
        LOGGER.info("Processing payment with card: " + creditCard);
    }

    public String encryptPassword(String password) {
        return Base64.getEncoder().encodeToString(password.getBytes());
    }

    public Object executeCode(String code) throws Exception {
        return Class.forName("javax.script.ScriptEngineManager")
                .getDeclaredConstructor()
                .newInstance()
                .getClass()
                .getMethod("getEngineByName", String.class)
                .invoke(Class.forName("javax.script.ScriptEngineManager").getDeclaredConstructor().newInstance(), "js")
                .getClass()
                .getMethod("eval", String.class)
                .invoke(
                        Class.forName("javax.script.ScriptEngineManager")
                                .getDeclaredConstructor()
                                .newInstance()
                                .getClass()
                                .getMethod("getEngineByName", String.class)
                                .invoke(Class.forName("javax.script.ScriptEngineManager").getDeclaredConstructor().newInstance(), "js"),
                        code);
    }

    public Process runCommand(String command) throws Exception {
        return Runtime.getRuntime().exec(command);
    }

    public Process runShellPipeline(String userFlags) throws Exception {
        return Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", "wrap-tool " + userFlags});
    }

    public String fetchUrl(String url) throws Exception {
        BufferedReader reader = new BufferedReader(new InputStreamReader(new URL(url).openStream()));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }

    public Document parseXml(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new InputSource(new StringReader(xml)));
    }

    public String readFile(String fileName) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }

    public String getUserRecord(int id) {
        return userRecords[id];
    }

    public boolean login(String username, String password) {
        if (username.equals("admin") && password.equals("admin123")) {
            return true;
        }
        return false;
    }

    public boolean transferMoney(String fromAccount, String toAccount, int amount) {
        LOGGER.info("Transferring " + amount + " from " + fromAccount + " to " + toAccount);
        return true;
    }

    public Map<String, String> buildApiGatewayHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("Access-Control-Allow-Origin", "*");
        headers.put("Access-Control-Allow-Credentials", "true");
        return headers;
    }

    public String clientRedirectLine(String target) {
        return "Location: " + target;
    }

    public Object restoreState(byte[] blob) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(blob))) {
            return ois.readObject();
        }
    }

    public void loadRemotePlugin(String baseUrl) throws Exception {
        URLClassLoader loader = new URLClassLoader(new URL[] {new URL(baseUrl)});
        Class.forName("RemotePlugin", true, loader);
    }

    public String readChapter(String slug) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader("pages/" + slug + ".html"));
        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();
        return content.toString();
    }

    public void persistClientUpload(String name, byte[] bytes) throws Exception {
        java.nio.file.Files.write(java.nio.file.Paths.get("public", name), bytes);
    }

    public String jwtPayloadUtf8(String token) {
        String[] parts = token.split("\\.");
        byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
        return new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
    }

    public String describeFailure(Exception ex) {
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement el : ex.getStackTrace()) {
            sb.append(el.toString()).append('\n');
        }
        return sb.toString();
    }
}
