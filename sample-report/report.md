# Security Assessment Report

**Target:** `/home/hatch/workspace/vuln-lab/demo-app`  
**Scanned:** 2026-10-13T05:20:50.723Z  
**Files scanned:** 1 source files, 1 package manifest(s)  
**Scanner:** legacy-vuln-lab scanner v1.0.0

> Static assessment only. Findings are indicators for authorized review, not proof of exploitability in a deployed environment.

## Executive summary

11 finding(s): 4 critical, 5 high, 2 medium.

**Critical findings require immediate attention.** At least one issue class present in this codebase is sufficient, on its own, to compromise the application and the data it holds.

## Findings

### 1. [CRITICAL] minimist: prototype pollution via crafted CLI arguments

- **Rule:** `ADV-MINIMIST-CVE-2021-44906` · **CVE:** CVE-2021-44906 · **Class:** CWE-1321
- **Location:** `package.json` line 6
- **Dependency:** minimist 1.2.5
- **Evidence:** `"minimist": "1.2.5"`
- **Business impact:** This application pins minimist 1.2.5, which is affected by CVE-2021-44906 (minimist: prototype pollution via crafted CLI arguments). Public technical details and exploit tooling exist for this vulnerability; internet-wide scanners actively probe for it. A known-vulnerable dependency converts an unknown risk into a scheduled one.
- **Remediation:** Upgrade minimist to 1.2.6 or later, re-run the dependency audit, and add automated dependency monitoring (e.g. Dependabot/Renovate) so pinned versions cannot silently age into known-vulnerable releases.

### 2. [CRITICAL] Dynamic code evaluation (eval / Function constructor)

- **Rule:** `EVAL-USE` · **Class:** CWE-95
- **Location:** `app.js` line 97
- **Evidence:** `return send(res, 200, String(eval(expr)));`
- **Business impact:** If any part of the evaluated string is influenced by a request, an attacker achieves remote code execution with the full privileges of the application process — complete server compromise, not just data exposure.
- **Remediation:** Remove eval/Function entirely. Replace dynamic behavior with lookup tables, configuration, or a vetted templating engine that does not execute code.

### 3. [CRITICAL] SQL query built by string concatenation (SQL injection)

- **Rule:** `SQLI-CONCAT` · **Class:** CWE-89
- **Location:** `app.js` line 66
- **Evidence:** `const query = "SELECT * FROM users WHERE username = '" + username +`
- **Business impact:** An unauthenticated attacker can manipulate the query through normal input fields to bypass authentication and read or modify the entire database. In a system holding patient records this is a reportable data-breach scenario and the most commonly exploited web flaw in healthcare breaches.
- **Remediation:** Use parameterized queries / prepared statements everywhere (never interpolate input into SQL text). Add a least-privilege database account and automated regression tests with injection payloads.

### 4. [CRITICAL] SQL query built by string concatenation (SQL injection)

- **Rule:** `SQLI-CONCAT` · **Class:** CWE-89
- **Location:** `app.js` line 80
- **Evidence:** `const query = "SELECT id, name, condition FROM patients WHERE name LIKE '%" + q + "%'";`
- **Business impact:** An unauthenticated attacker can manipulate the query through normal input fields to bypass authentication and read or modify the entire database. In a system holding patient records this is a reportable data-breach scenario and the most commonly exploited web flaw in healthcare breaches.
- **Remediation:** Use parameterized queries / prepared statements everywhere (never interpolate input into SQL text). Add a least-privilege database account and automated regression tests with injection payloads.

### 5. [HIGH] axios: regular expression denial of service (ReDoS)

- **Rule:** `ADV-AXIOS-CVE-2021-3749` · **CVE:** CVE-2021-3749 · **Class:** CWE-400
- **Location:** `package.json` line 3
- **Dependency:** axios 0.21.1
- **Evidence:** `"axios": "0.21.1"`
- **Business impact:** This application pins axios 0.21.1, which is affected by CVE-2021-3749 (axios: regular expression denial of service (ReDoS)). Public technical details and exploit tooling exist for this vulnerability; internet-wide scanners actively probe for it. A known-vulnerable dependency converts an unknown risk into a scheduled one.
- **Remediation:** Upgrade axios to 0.21.2 or later, re-run the dependency audit, and add automated dependency monitoring (e.g. Dependabot/Renovate) so pinned versions cannot silently age into known-vulnerable releases.

### 6. [HIGH] jsonwebtoken: improper key handling allows signature verification bypass with crafted payloads

- **Rule:** `ADV-JWT-CVE-2022-23529` · **CVE:** CVE-2022-23529 · **Class:** CWE-347
- **Location:** `package.json` line 4
- **Dependency:** jsonwebtoken 8.5.1
- **Evidence:** `"jsonwebtoken": "8.5.1"`
- **Business impact:** This application pins jsonwebtoken 8.5.1, which is affected by CVE-2022-23529 (jsonwebtoken: improper key handling allows signature verification bypass with crafted payloads). Public technical details and exploit tooling exist for this vulnerability; internet-wide scanners actively probe for it. A known-vulnerable dependency converts an unknown risk into a scheduled one.
- **Remediation:** Upgrade jsonwebtoken to 9.0.0 or later, re-run the dependency audit, and add automated dependency monitoring (e.g. Dependabot/Renovate) so pinned versions cannot silently age into known-vulnerable releases.

### 7. [HIGH] lodash: command injection via _.template imports key names

- **Rule:** `ADV-LODASH-CVE-2021-23337` · **CVE:** CVE-2021-23337 · **Class:** CWE-94
- **Location:** `package.json` line 5
- **Dependency:** lodash 4.17.20
- **Evidence:** `"lodash": "4.17.20"`
- **Business impact:** This application pins lodash 4.17.20, which is affected by CVE-2021-23337 (lodash: command injection via _.template imports key names). Public technical details and exploit tooling exist for this vulnerability; internet-wide scanners actively probe for it. A known-vulnerable dependency converts an unknown risk into a scheduled one.
- **Remediation:** Upgrade lodash to 4.17.21 or later, re-run the dependency audit, and add automated dependency monitoring (e.g. Dependabot/Renovate) so pinned versions cannot silently age into known-vulnerable releases.

### 8. [HIGH] Hardcoded secret committed to source code

- **Rule:** `HARDCODED-SECRET` · **Class:** CWE-798
- **Location:** `app.js` line 18
- **Evidence:** `const BILLING_API_SECRET = '••••••';`
- **Business impact:** The secret is exposed to everyone who has ever had repository access — employees, contractors, backups, and any future repo leak. Rotation is the only remedy once committed, and abuse (e.g. of a billing key) is billed to you.
- **Remediation:** Rotate the exposed credential immediately, then move secrets to environment variables or a secrets manager. Scrub git history and add pre-commit secret scanning.

### 9. [HIGH] Weak hash (MD5/SHA1) protecting passwords or sensitive data

- **Rule:** `WEAK-CRYPTO` · **Class:** CWE-327
- **Location:** `app.js` line 23
- **Evidence:** `return crypto.createHash('md5').update(pw).digest('hex');`
- **Business impact:** MD5 and SHA1 are fast hashes: a single consumer GPU tests billions of candidates per second. If the credential store is ever exposed, effectively every password falls within hours, and users reuse those passwords elsewhere.
- **Remediation:** Rehash passwords with a password-specific KDF (bcrypt, scrypt, or Argon2id) with per-user salts. Force a password reset on next login for existing accounts.

### 10. [MEDIUM] No HTTP security headers configured

- **Rule:** `MISSING-SECURITY-HEADERS` · **Class:** CWE-693
- **Location:** `app.js` line 50
- **Evidence:** `const server = http.createServer((req, res) => {`
- **Business impact:** Without headers such as Content-Security-Policy and X-Content-Type-Options, the application is exposed to clickjacking, MIME-confusion, and easier cross-site scripting exploitation — low-effort attacks that automated tooling attempts against every site.
- **Remediation:** Add a hardened header set (helmet for Express, or explicit response headers) including Content-Security-Policy, X-Content-Type-Options: nosniff, and frame protections; verify with a response-header scan.

### 11. [MEDIUM] Verbose error output leaks stack traces / internals

- **Rule:** `VERBOSE-ERRORS` · **Class:** CWE-209
- **Location:** `app.js` line 47
- **Evidence:** `send(res, 500, JSON.stringify({ error: err.message, stack: err.stack, query }), 'application/json');`
- **Business impact:** Stack traces and raw queries hand attackers a map of the codebase — file paths, library versions, table and column names — dramatically shortening the time needed to craft a working exploit against the other flaws present.
- **Remediation:** Return generic error messages to clients; log full detail server-side only. Ensure NODE_ENV=production error handling is enforced and covered by a test that forces an exception.

## Methodology

Dependency versions pinned in package manifests were compared against a bundled advisory fixture modeled on public CVE records. Source files were checked for high-risk patterns: SQL string construction, dynamic code evaluation, weak password hashing, hardcoded secrets, verbose error output, and missing HTTP security-header configuration. Static findings indicate where a flaw class is present; a qualified reviewer should confirm exploitability in context before remediation work is scheduled.
