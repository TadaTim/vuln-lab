# Legacy Vulnerability Lab

A security **demonstration** and **authorized-assessment** toolkit.

It pairs a deliberately vulnerable sample application with a generic
assessment scanner, so a prospective client can watch — on a system built for
the purpose — exactly how legacy code fails, how an attacker walks through it,
and what a professional assessment report on their own codebase would look
like.

> ## ⚠️ Authorized use only
>
> The scanner and these techniques may be used **only on systems you own or
> have explicit written authorization to test.** Unauthorized testing of
> third-party systems is illegal. The exploit demonstration in this repository
> is hard-locked to `localhost` and to the bundled sample app — it refuses
> every other target by design, with no override.

---

## The centerpiece: the assessment scanner

`scanner/` is a ready-to-run diagnostic for **any** Node/JavaScript codebase.
It contains no assumptions about the demo app — point it at a client's
repository (with their authorization) and it produces a client-style
assessment report for whatever it finds.

```bash
# Run the diagnostic against a codebase:
node scanner/scan.js <path-to-codebase> [--out <output-dir>]

# e.g.
npm run scan -- /path/to/client/repo
```

It performs two kinds of checks:

1. **Dependency audit** — every version pinned in `package.json` files is
   compared against a bundled advisory fixture (`scanner/fixtures/advisories.json`)
   modeled on real public CVE records (lodash, minimist, jsonwebtoken, axios,
   express, semver, …), each with severity and fixed-version guidance.
2. **Static pattern checks** — source files are scanned for the flaw classes
   that dominate real-world legacy breaches: SQL built by string concatenation
   (CWE-89), `eval`/`Function` code execution (CWE-95), MD5/SHA1 password
   hashing (CWE-327), hardcoded secrets (CWE-798), stack-trace leakage
   (CWE-209), and missing HTTP security headers (CWE-693).

Output (written to the output directory):

- `report.md` — client-ready Markdown: executive summary, per-finding
  severity, evidence with `file:line`, business-impact language, and
  remediation guidance.
- `report.json` — the same findings, machine-readable.

Static findings are indicators, not proof of exploitability — the report says
so, and a reviewer confirms context before remediation is scheduled. That
honesty is part of the deliverable.

## The built-in test case: `demo-app/`

A small "legacy-style" patient-records web app (plain Node, in-memory SQLite,
all patient data fictional) with **11 planted, cataloged vulnerabilities** —
SQL injection in login and search, MD5 password hashing, a hardcoded live API
secret, four known-vulnerable pinned dependencies, no security headers,
stack-trace leakage, and an `eval()` endpoint. The full catalog, with the
CWE/CVE class of each flaw, is in
[`demo-app/PLANTED-FLAWS.md`](demo-app/PLANTED-FLAWS.md).

It exists to prove the scanner works: `npm test` asserts the scanner finds
exactly the cataloged flaws — no misses, no extras — and it serves as the live
target for the demonstration below. **Never deploy it.**

## The live demonstration: `exploit-demo/`

Shows, in about five seconds, what the scanner's top finding means in
practice:

1. A login attempt with a wrong password is rejected (HTTP 401).
2. The username `' OR '1'='1' -- ` is submitted instead — and the app
   authenticates the attacker as **admin**, no password needed.
3. A `UNION SELECT` through the search box returns the credential store,
   exposing every password as an unsalted MD5 hash.

The script spawns the demo app itself on localhost, and its target guard is
hard-coded: any host other than `localhost` / `127.0.0.1` / `::1` is refused
before any network activity (covered by tests, including a CLI-level check).

## Run the full demo end-to-end

```bash
# 1. Live exploit demonstration (starts the demo app, attacks it, shuts down)
npm run demo

# 2. Scanner assessment of the demo app
node scanner/scan.js demo-app --out sample-report
cat sample-report/report.md

# 3. Start the demo app yourself and look around (fictional data only)
cd demo-app && PORT=3000 node app.js   # http://127.0.0.1:3000

# 4. Full test suite
npm test
```

No installation step is required: everything runs on plain Node (the demo app
uses the built-in `node:sqlite`). The vulnerable versions in
`demo-app/package.json` are pins for the dependency audit — the app itself
loads no third-party packages.

## Sample of the generated report

From [`sample-report/report.md`](sample-report/report.md) (scanner output on
the bundled demo app):

> ## Executive summary
>
> 11 finding(s): 4 critical, 5 high, 2 medium.
>
> **Critical findings require immediate attention.** At least one issue class
> present in this codebase is sufficient, on its own, to compromise the
> application and the data it holds.
>
> ### 3. [CRITICAL] SQL query built by string concatenation (SQL injection)
>
> - **Rule:** `SQLI-CONCAT` · **Class:** CWE-89
> - **Location:** `app.js` line 66
> - **Evidence:** `const query = "SELECT * FROM users WHERE username = '" + username +`
> - **Business impact:** An unauthenticated attacker can manipulate the query
>   through normal input fields to bypass authentication and read or modify
>   the entire database. In a system holding patient records this is a
>   reportable data-breach scenario and the most commonly exploited web flaw
>   in healthcare breaches.
> - **Remediation:** Use parameterized queries / prepared statements
>   everywhere (never interpolate input into SQL text). …

## Repository layout

```
demo-app/       Deliberately vulnerable sample app + PLANTED-FLAWS.md catalog
scanner/        Generic assessment scanner (scan.js) + advisory fixture
exploit-demo/   Localhost-locked SQL-injection demonstration
tests/          Scanner-vs-catalog assertions, guard tests, end-to-end exploit test
sample-report/  Scanner output on the demo app (report.md / report.json)
```

## Validation status

`npm test` — 27 checks, all passing: scanner findings match the planted-flaws
catalog exactly (11 findings, per-rule counts verified), the localhost guard
rejects non-local targets at both the API and CLI level, and the exploit demo
completes the login bypass and credential extraction against the bundled app.
