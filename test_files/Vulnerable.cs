using System;
using System.Data.SqlClient;
using System.Web;
using System.Security.Cryptography;
using System.Text;

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
} 