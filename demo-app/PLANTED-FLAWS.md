# Planted Flaws Catalog — demo-app

Every flaw below is **intentional**, planted in the demo app so the assessment
scanner in `../scanner/` has real findings to produce and the exploit demo in
`../exploit-demo/` has a real target. Each entry lists where the flaw lives,
the weakness class it represents (CWE / CVE), and the scanner rule expected to
catch it.

| ID | Flaw | Location | Class | Scanner rule |
|----|------|----------|-------|--------------|
| FLAW-001 | SQL injection in staff login — query built by string concatenation | `app.js` (`/login`) | CWE-89 | `SQLI-CONCAT` |
| FLAW-002 | SQL injection in patient search — UNION SELECT can exfiltrate the users table | `app.js` (`/search`) | CWE-89 | `SQLI-CONCAT` |
| FLAW-003 | Passwords hashed with MD5 (fast, broken) | `app.js` (`hashPassword`) | CWE-327 / CWE-916 | `WEAK-CRYPTO` |
| FLAW-004 | Hardcoded live billing API secret in source | `app.js` (`BILLING_API_SECRET`) | CWE-798 | `HARDCODED-SECRET` |
| FLAW-005 | Outdated dependency: lodash 4.17.20 — command injection via `_.template` | `package.json` | CVE-2021-23337 | `ADV-LODASH-CVE-2021-23337` |
| FLAW-006 | Outdated dependency: minimist 1.2.5 — prototype pollution | `package.json` | CVE-2021-44906 | `ADV-MINIMIST-CVE-2021-44906` |
| FLAW-007 | Outdated dependency: jsonwebtoken 8.5.1 — improper key verification | `package.json` | CVE-2022-23529 | `ADV-JWT-CVE-2022-23529` |
| FLAW-008 | Outdated dependency: axios 0.21.1 — ReDoS in `follow-redirects` handling | `package.json` | CVE-2021-3749 | `ADV-AXIOS-CVE-2021-3749` |
| FLAW-009 | No security headers anywhere (no CSP, no X-Content-Type-Options, …) and no `helmet` | `app.js` (whole app) | CWE-693 | `MISSING-SECURITY-HEADERS` |
| FLAW-010 | Verbose errors return stack traces and raw SQL to the requester | `app.js` (`handleError`) | CWE-209 | `VERBOSE-ERRORS` |
| FLAW-011 | `eval()` executed on request input in the "report formatter" | `app.js` (`/report`) | CWE-95 | `EVAL-USE` |

Expected scanner result against this directory: **11 findings** —
`SQLI-CONCAT` ×2, `WEAK-CRYPTO` ×1, `HARDCODED-SECRET` ×1,
`ADV-LODASH-CVE-2021-23337` ×1, `ADV-MINIMIST-CVE-2021-44906` ×1,
`ADV-JWT-CVE-2022-23529` ×1, `ADV-AXIOS-CVE-2021-3749` ×1,
`MISSING-SECURITY-HEADERS` ×1, `VERBOSE-ERRORS` ×1, `EVAL-USE` ×1.

Machine-readable expectations (used by `../tests/`):

```json
{
  "totalFindings": 11,
  "byRule": {
    "SQLI-CONCAT": 2,
    "WEAK-CRYPTO": 1,
    "HARDCODED-SECRET": 1,
    "ADV-LODASH-CVE-2021-23337": 1,
    "ADV-MINIMIST-CVE-2021-44906": 1,
    "ADV-JWT-CVE-2022-23529": 1,
    "ADV-AXIOS-CVE-2021-3749": 1,
    "MISSING-SECURITY-HEADERS": 1,
    "VERBOSE-ERRORS": 1,
    "EVAL-USE": 1
  }
}
```
