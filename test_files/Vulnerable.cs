using System;
using System.Data.SqlClient;
using System.Web;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Net;
using System.Diagnostics;
using System.Xml;
using System.Reflection;

public class VulnerableCode
{
    // SQL Injection vulnerability
    public string GetUserData(string username)
    {
        using (SqlConnection conn = new SqlConnection("connection_string"))
        {
            // Vulnerable: String concatenation in SQL
            string query = "SELECT * FROM Users WHERE Username = '" + username + "'";
            SqlCommand cmd = new SqlCommand(query, conn);
            return cmd.ExecuteScalar()?.ToString();
        }
    }

    // XSS vulnerability
    public string RenderUserInput(string input)
    {
        // Vulnerable: Direct HTML output
        return $"<div class='user-content'>{input}</div>";
    }

    // Insufficient Input Validation
    public int ProcessAge(string age)
    {
        // Vulnerable: No validation
        return int.Parse(age) * 12;
    }

    // Sensitive Data Exposure
    public void LogUserData(string username, string password)
    {
        // Vulnerable: Logging sensitive data
        Console.WriteLine($"User created - Username: {username}, Password: {password}");
    }

    // Session Management Issues
    private static Dictionary<string, string> sessions = new Dictionary<string, string>();
    public string CreateSession(string userId)
    {
        // Vulnerable: Predictable session token
        string token = userId + DateTime.Now.Ticks;
        sessions[userId] = token;
        return token;
    }

    // Security Misconfiguration
    private const string AdminPassword = "admin123";  // Vulnerable: Hardcoded credential

    // Sensitive Data Logging
    public void ProcessPayment(string creditCard)
    {
        // Vulnerable: Logging sensitive data
        Console.WriteLine($"Processing payment with card: {creditCard}");
    }

    // Insecure Cryptographic Usage
    public string HashPassword(string password)
    {
        // Vulnerable: Using weak hashing
        using (MD5 md5 = MD5.Create())
        {
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hash);
        }
    }

    // Remote Code Execution (RCE) vulnerability
    public object ExecuteCode(string code)
    {
        // Vulnerable: Dynamic code execution
        return Eval(code);
    }

    private object Eval(string code)
    {
        // Mock implementation of code evaluation
        Microsoft.CSharp.CSharpCodeProvider provider = new Microsoft.CSharp.CSharpCodeProvider();
        System.CodeDom.Compiler.CompilerParameters parameters = new System.CodeDom.Compiler.CompilerParameters();
        // Vulnerable implementation
        return null; // Simplified for example
    }

    public string RunCommand(string command)
    {
        // Vulnerable: Direct command execution
        Process process = new Process();
        process.StartInfo.FileName = "cmd.exe";
        process.StartInfo.Arguments = "/c " + command;
        process.StartInfo.RedirectStandardOutput = true;
        process.StartInfo.UseShellExecute = false;
        process.Start();
        string output = process.StandardOutput.ReadToEnd();
        process.WaitForExit();
        return output;
    }

    // Server-Side Request Forgery (SSRF) vulnerability
    public string FetchUrl(string url)
    {
        // Vulnerable: No URL validation
        using (WebClient client = new WebClient())
        {
            return client.DownloadString(url);
        }
    }

    // XML External Entity (XXE) vulnerability
    public XmlDocument ParseXml(string xml)
    {
        // Vulnerable: No protection against XXE
        XmlDocument doc = new XmlDocument();
        doc.XmlResolver = new XmlUrlResolver(); // Allows XXE
        doc.LoadXml(xml);
        return doc;
    }

    // Path Traversal vulnerability
    public string ReadFile(string fileName)
    {
        // Vulnerable: No path validation
        return File.ReadAllText(fileName);
    }

    // Insecure Direct Object Reference (IDOR) vulnerability
    private string[] UserRecords = {"admin:secret", "user:password"};
    
    public string GetUserRecord(int id)
    {
        // Vulnerable: No access control
        return UserRecords[id];
    }
    
    // Authentication Issues
    public bool Login(string username, string password)
    {
        // Vulnerable: Weak authentication
        if (username == "admin" && password == "admin123")
        {
            return true;
        }
        return false;
    }
    
    // Cross-Site Request Forgery (CSRF) vulnerability
    public bool TransferMoney(string fromAccount, string toAccount, int amount)
    {
        // Vulnerable: No CSRF protection
        Console.WriteLine($"Transferring {amount} from {fromAccount} to {toAccount}");
        // Process transfer without validating request origin
        return true;
    }
} 