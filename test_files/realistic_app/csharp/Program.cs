/*
Realistic vulnerable fixture: a minimal ASP.NET Core help-desk API.

Static test file for OASIS. Contains dangerous sinks on purpose.
No real database or external services are required.
*/

using System.Data.SqlClient;
using System.Diagnostics;
using System.Text;
using System.Web;
using System.Xml;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

const string AdminPassword = "admin123";
const string DbConnectionString = "Server=db.internal;Database=appdb;User Id=appuser;Password=SuperSecret123;";

// ---------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------

app.MapGet("/ticket/search", (string title) =>
{
    // VULNERABLE: raw concatenation.
    using var conn = new SqlConnection(DbConnectionString);
    conn.Open();
    using var cmd = new SqlCommand("SELECT * FROM tickets WHERE title = '" + title + "'", conn);
    using var reader = cmd.ExecuteReader();
    var results = new List<string>();
    while (reader.Read()) results.Add(reader.GetString(0));
    return Results.Ok(results);
});

app.MapGet("/ticket/search-safe", (string title) =>
{
    // SAFE: parameterized.
    using var conn = new SqlConnection(DbConnectionString);
    conn.Open();
    using var cmd = new SqlCommand("SELECT * FROM tickets WHERE title = @title", conn);
    cmd.Parameters.AddWithValue("@title", title);
    using var reader = cmd.ExecuteReader();
    var results = new List<string>();
    while (reader.Read()) results.Add(reader.GetString(0));
    return Results.Ok(results);
});

app.MapGet("/ticket/{id:int}", (int id) =>
{
    // VULNERABLE: path value concatenated.
    using var conn = new SqlConnection(DbConnectionString);
    conn.Open();
    using var cmd = new SqlCommand("SELECT * FROM tickets WHERE id = " + id, conn);
    using var reader = cmd.ExecuteReader();
    return Results.Ok(reader.Read() ? reader.GetString(0) : null);
});

// ---------------------------------------------------------------------------
// Command injection
// ---------------------------------------------------------------------------

app.MapGet("/admin/ping", (string host) =>
{
    // VULNERABLE: shell command with user input.
    var psi = new ProcessStartInfo("cmd.exe", "/c ping " + host)
    {
        RedirectStandardOutput = true,
        UseShellExecute = false,
    };
    var proc = Process.Start(psi)!;
    string output = proc.StandardOutput.ReadToEnd();
    proc.WaitForExit();
    return Results.Ok(output);
});

app.MapGet("/admin/ping-safe", (string host) =>
{
    // SAFE: allowlist and no shell.
    if (!System.Text.RegularExpressions.Regex.IsMatch(host, @"^[a-zA-Z0-9\.\-]{1,253}$"))
        return Results.BadRequest("invalid host");
    var psi = new ProcessStartInfo("ping", host)
    {
        RedirectStandardOutput = true,
        UseShellExecute = false,
    };
    var proc = Process.Start(psi)!;
    string output = proc.StandardOutput.ReadToEnd();
    proc.WaitForExit();
    return Results.Ok(output);
});

// ---------------------------------------------------------------------------
// XSS
// ---------------------------------------------------------------------------

app.MapGet("/ticket/{id:int}/render", (int id) =>
{
    // VULNERABLE: unescaped output.
    var ticket = LoadTicket(id);
    return Results.Content($"<h1>{ticket.Title}</h1><p>{ticket.Body}</p>", "text/html");
});

app.MapGet("/ticket/{id:int}/render-safe", (int id) =>
{
    // SAFE: HTML-encoded.
    var ticket = LoadTicket(id);
    return Results.Content(
        $"<h1>{HttpUtility.HtmlEncode(ticket.Title)}</h1><p>{HttpUtility.HtmlEncode(ticket.Body)}</p>",
        "text/html");
});

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------

app.MapGet("/docs/{*path}", (string path) =>
{
    // VULNERABLE: user path joined directly.
    string fullPath = Path.Combine("docs", path);
    return Results.File(File.ReadAllBytes(fullPath));
});

app.MapGet("/docs-safe/{filename}", (string filename) =>
{
    // PARTIALLY SAFE: basename only.
    string safeName = Path.GetFileName(filename);
    string baseDir = Path.GetFullPath("docs");
    string target = Path.GetFullPath(Path.Combine(baseDir, safeName));
    if (!target.StartsWith(baseDir + Path.DirectorySeparatorChar))
        return Results.BadRequest("invalid path");
    return Results.File(File.ReadAllBytes(target));
});

// ---------------------------------------------------------------------------
// XXE
// ---------------------------------------------------------------------------

app.MapPost("/xml/parse", async (HttpRequest request) =>
{
    // VULNERABLE: external entities enabled.
    string xml = await new StreamReader(request.Body).ReadToEndAsync();
    var doc = new XmlDocument();
    doc.XmlResolver = new XmlUrlResolver();
    doc.LoadXml(xml);
    return Results.Ok(doc.DocumentElement?.Name);
});

app.MapPost("/xml/parse-safe", async (HttpRequest request) =>
{
    // SAFE: entities disabled.
    string xml = await new StreamReader(request.Body).ReadToEndAsync();
    var settings = new XmlReaderSettings { DtdProcess = DtdProcess.Prohibit };
    using var reader = XmlReader.Create(new StringReader(xml), settings);
    var doc = new XmlDocument();
    doc.Load(reader);
    return Results.Ok(doc.DocumentElement?.Name);
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

record Ticket(int Id, string Title, string Body);

static Ticket LoadTicket(int id) =>
    new(id, "Sample ticket", "Sample body with <script>alert(1)</script>");

app.Run();
