/**
 * Realistic vulnerable fixture: a minimal Express feedback / upload API.
 *
 * Static test file for OASIS. Contains dangerous sinks on purpose.
 * No real DB, no real external services.
 */

const express = require('express');
const sqlite3 = require('sqlite3');
const child_process = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const url = require('url');

const app = express();
app.use(express.json());

const ADMIN_PASSWORD = 'admin123';
const DB_PATH = './feedback.db';

// ---------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------

app.get('/feedback/search', (req, res) => {
    // VULNERABLE: direct concatenation.
    const q = req.query.q || '';
    const db = new sqlite3.Database(DB_PATH);
    db.all("SELECT * FROM feedback WHERE body LIKE '%" + q + "%'", (err, rows) => {
        res.json(rows || []);
    });
});

app.get('/feedback/search-safe', (req, res) => {
    // SAFE: parameterized.
    const q = req.query.q || '';
    const db = new sqlite3.Database(DB_PATH);
    db.all("SELECT * FROM feedback WHERE body LIKE ?", ['%' + q + '%'], (err, rows) => {
        res.json(rows || []);
    });
});

// ---------------------------------------------------------------------------
// Command injection
// ---------------------------------------------------------------------------

app.get('/admin/ping', (req, res) => {
    // VULNERABLE: shell with user input.
    const host = req.query.host || '';
    child_process.exec('ping -c 1 ' + host, (err, stdout) => {
        res.json({ output: stdout });
    });
});

app.get('/admin/ping-safe', (req, res) => {
    // SAFE: allowlist + no shell.
    const host = req.query.host || '';
    if (!/^[a-zA-Z0-9.\-]{1,253}$/.test(host)) {
        return res.status(400).json({ error: 'invalid host' });
    }
    child_process.execFile('ping', ['-c', '1', host], (err, stdout) => {
        res.json({ output: stdout });
    });
});

// ---------------------------------------------------------------------------
// XSS
// ---------------------------------------------------------------------------

app.get('/feedback/:id', (req, res) => {
    // VULNERABLE: unescaped user content.
    const body = loadFeedback(req.params.id);
    res.send(`<h1>Feedback</h1><p>${body}</p>`);
});

app.get('/feedback/:id/safe', (req, res) => {
    // SAFE: escaped.
    const body = escapeHtml(loadFeedback(req.params.id));
    res.send(`<h1>Feedback</h1><p>${body}</p>`);
});

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------

app.get('/uploads/:filename', (req, res) => {
    // VULNERABLE: user filename.
    const target = path.join('uploads', req.params.filename);
    res.sendFile(path.resolve(target));
});

app.get('/uploads-safe/:filename', (req, res) => {
    // PARTIALLY SAFE: basename only.
    const safeName = path.basename(req.params.filename);
    const baseDir = path.resolve('uploads');
    const target = path.resolve(path.join(baseDir, safeName));
    if (!target.startsWith(baseDir + path.sep)) {
        return res.status(400).json({ error: 'invalid path' });
    }
    res.sendFile(target);
});

// ---------------------------------------------------------------------------
// SSRF + open redirect
// ---------------------------------------------------------------------------

app.get('/fetch', (req, res) => {
    // VULNERABLE: arbitrary URL.
    const target = req.query.url || '';
    const client = target.startsWith('https:') ? https : http;
    client.get(target, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => res.send(data));
    });
});

app.get('/fetch-safe', (req, res) => {
    // SAFE: host allowlist.
    const allowed = new Set(['api.example.com', 'status.example.com']);
    const target = req.query.url || '';
    const parsed = url.parse(target);
    if (!allowed.has(parsed.hostname)) {
        return res.status(400).json({ error: 'host not allowed' });
    }
    const client = parsed.protocol === 'https:' ? https : http;
    client.get(target, (resp) => {
        let data = '';
        resp.on('data', chunk => data += chunk);
        resp.on('end', () => res.send(data));
    });
});

app.get('/goto', (req, res) => {
    // VULNERABLE: open redirect.
    res.redirect(req.query.next || '/');
});

app.get('/goto-safe', (req, res) => {
    // SAFE: allowlist.
    const allowed = ['/dashboard', '/feedback', '/logout'];
    let next = req.query.next || '/';
    if (!allowed.includes(next)) next = '/';
    res.redirect(next);
});

// ---------------------------------------------------------------------------
// Weak crypto / hardcoded secret
// ---------------------------------------------------------------------------

app.get('/login', (req, res) => {
    // VULNERABLE: hardcoded admin backdoor.
    if (req.query.username === 'admin' && req.query.password === ADMIN_PASSWORD) {
        return res.json({ token: Buffer.from('admin_session').toString('base64') });
    }
    res.status(401).json({ error: 'unauthorized' });
});

function hashPasswordVulnerable(password) {
    // VULNERABLE: MD5.
    const crypto = require('crypto');
    return crypto.createHash('md5').update(password).digest('hex');
}

// ---------------------------------------------------------------------------
// Insecure deserialization
// ---------------------------------------------------------------------------

app.post('/import', (req, res) => {
    // VULNERABLE: vm / eval import.
    const code = Buffer.from(req.body.payload, 'base64').toString();
    const result = eval(code);  // eslint-disable-line no-eval
    res.json({ result });
});

app.post('/import-json', (req, res) => {
    // SAFE: JSON only.
    res.json({ imported: req.body });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function loadFeedback(id) {
    return `<script>alert('feedback ${id}')</script>`;
}

function escapeHtml(text) {
    return text.replace(/&/g, '&amp;')
               .replace(/</g, '&lt;')
               .replace(/>/g, '&gt;')
               .replace(/"/g, '&quot;')
               .replace(/'/g, '&#x27;');
}

app.listen(3000, () => {
    // Static fixture: server only runs if invoked directly.
});
