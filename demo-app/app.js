'use strict';
/*
 * legacy-patient-records — a DELIBERATELY VULNERABLE demo application.
 *
 * This code intentionally contains classic legacy flaws (see PLANTED-FLAWS.md)
 * so the assessment scanner and exploit demo in this repository have something
 * real to find. It is written the way rushed legacy code gets written.
 *
 * DO NOT deploy this. DO NOT copy these patterns into real software.
 * All patient data below is fictional.
 */
const http = require('http');
const crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');

// FLAW-004 (CWE-798): hardcoded API secret committed to source control.
// Anyone with repo access — including every ex-contractor — has this key.
const BILLING_API_SECRET = "DEMO-ONLY-KEY-0000111122223333" + 'x7QpLIVESECRET4417zz';

// FLAW-003 (CWE-327/CWE-916): MD5 is a fast, broken hash. Passwords hashed
// with MD5 can be cracked at billions of guesses per second on one GPU.
function hashPassword(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

const db = new DatabaseSync(':memory:');
db.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
         CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT, condition TEXT, ssn_last4 TEXT);`);
const insUser = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
insUser.run('admin', hashPassword('admin123'), 'administrator');
insUser.run('nurse.joy', hashPassword('carepass'), 'nurse');
const insPat = db.prepare('INSERT INTO patients (name, condition, ssn_last4) VALUES (?, ?, ?)');
insPat.run('Alice Example', 'Hypertension', '4417');
insPat.run('Bob Sample', 'Type 2 Diabetes', '2093');
insPat.run('Carol Placeholder', 'Asthma', '7781');

function send(res, status, body, type = 'text/html') {
  // FLAW-009 (CWE-693): no security headers are ever set anywhere in this app —
  // no Content-Security-Policy, no X-Content-Type-Options, nothing.
  res.writeHead(status, { 'Content-Type': type });
  res.end(body);
}

function handleError(res, err, query) {
  // FLAW-010 (CWE-209): verbose errors leak the stack trace AND the raw SQL
  // query to whoever caused the error — a roadmap for an attacker.
  send(res, 500, JSON.stringify({ error: err.message, stack: err.stack, query }), 'application/json');
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (req.method === 'GET' && url.pathname === '/') {
      return send(res, 200, '<h1>Legacy Patient Records</h1><p>Staff portal. Use /login, /search?q=, /patient?id=</p>');
    }

    if (req.method === 'POST' && url.pathname === '/login') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        try {
          const { username = '', password = '' } = JSON.parse(body || '{}');
          // FLAW-001 (CWE-89): SQL built by string concatenation. Input like
          //   ' OR '1'='1' --
          // turns this into a query that matches every user.
          const query = "SELECT * FROM users WHERE username = '" + username +
                        "' AND password = '" + hashPassword(password) + "'";
          const user = db.prepare(query).get();
          if (user) return send(res, 200, JSON.stringify({ ok: true, welcome: user.username, role: user.role }), 'application/json');
          return send(res, 401, JSON.stringify({ ok: false, error: 'invalid credentials' }), 'application/json');
        } catch (err) { return handleError(res, err, 'login'); }
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/search') {
      const q = url.searchParams.get('q') || '';
      // FLAW-002 (CWE-89): same concatenation mistake in patient search.
      // A UNION SELECT here can pull the users table — credentials included.
      const query = "SELECT id, name, condition FROM patients WHERE name LIKE '%" + q + "%'";
      const rows = db.prepare(query).all();
      return send(res, 200, JSON.stringify(rows), 'application/json');
    }

    if (req.method === 'GET' && url.pathname === '/patient') {
      // The one endpoint a previous developer did correctly: bound parameter,
      // no concatenation. The scanner should NOT flag this one.
      const id = url.searchParams.get('id') || '0';
      const row = db.prepare('SELECT id, name, condition, ssn_last4 FROM patients WHERE id = ?').get(id);
      return send(res, 200, JSON.stringify(row || {}), 'application/json');
    }

    if (req.method === 'GET' && url.pathname === '/report') {
      // FLAW-011 (CWE-95): a "legacy report formatter" that eval()s a template
      // expression from the request. eval on user input is remote code execution.
      const expr = url.searchParams.get('expr') || "'no report'";
      return send(res, 200, String(eval(expr)));
    }

    return send(res, 404, 'not found');
  } catch (err) {
    return handleError(res, err, req.url);
  }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  server.listen(PORT, '127.0.0.1', () => console.log(`legacy-patient-records listening on 127.0.0.1:${PORT}`));
}
module.exports = { server, hashPassword };
