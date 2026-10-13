'use strict';
/*
 * Legacy Vulnerability Lab — assessment scanner.
 *
 * A fully generic static + dependency auditor for Node/JavaScript codebases.
 * It takes ANY target directory as an argument and has zero knowledge of the
 * bundled demo app: every check below is a general pattern or a data-driven
 * advisory comparison.
 *
 * Usage (authorized assessments only):
 *   node scanner/scan.js <target-dir> [--out <output-dir>]
 *
 * Emits report.json and report.md into the output directory.
 */
const fs = require('fs');
const path = require('path');

const ADVISORIES = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'fixtures', 'advisories.json'), 'utf8')
).advisories;

/* ---------------------------------- rules --------------------------------- */

const RULE_META = {
  'SQLI-CONCAT': {
    title: 'SQL query built by string concatenation (SQL injection)',
    severity: 'critical',
    cwe: 'CWE-89',
    impact:
      'An unauthenticated attacker can manipulate the query through normal input fields to bypass authentication and read or modify the entire database. In a system holding patient records this is a reportable data-breach scenario and the most commonly exploited web flaw in healthcare breaches.',
    remediation:
      'Use parameterized queries / prepared statements everywhere (never interpolate input into SQL text). Add a least-privilege database account and automated regression tests with injection payloads.',
  },
  'EVAL-USE': {
    title: 'Dynamic code evaluation (eval / Function constructor)',
    severity: 'critical',
    cwe: 'CWE-95',
    impact:
      'If any part of the evaluated string is influenced by a request, an attacker achieves remote code execution with the full privileges of the application process — complete server compromise, not just data exposure.',
    remediation:
      'Remove eval/Function entirely. Replace dynamic behavior with lookup tables, configuration, or a vetted templating engine that does not execute code.',
  },
  'WEAK-CRYPTO': {
    title: 'Weak hash (MD5/SHA1) protecting passwords or sensitive data',
    severity: 'high',
    cwe: 'CWE-327',
    impact:
      'MD5 and SHA1 are fast hashes: a single consumer GPU tests billions of candidates per second. If the credential store is ever exposed, effectively every password falls within hours, and users reuse those passwords elsewhere.',
    remediation:
      'Rehash passwords with a password-specific KDF (bcrypt, scrypt, or Argon2id) with per-user salts. Force a password reset on next login for existing accounts.',
  },
  'HARDCODED-SECRET': {
    title: 'Hardcoded secret committed to source code',
    severity: 'high',
    cwe: 'CWE-798',
    impact:
      'The secret is exposed to everyone who has ever had repository access — employees, contractors, backups, and any future repo leak. Rotation is the only remedy once committed, and abuse (e.g. of a billing key) is billed to you.',
    remediation:
      'Rotate the exposed credential immediately, then move secrets to environment variables or a secrets manager. Scrub git history and add pre-commit secret scanning.',
  },
  'MISSING-SECURITY-HEADERS': {
    title: 'No HTTP security headers configured',
    severity: 'medium',
    cwe: 'CWE-693',
    impact:
      'Without headers such as Content-Security-Policy and X-Content-Type-Options, the application is exposed to clickjacking, MIME-confusion, and easier cross-site scripting exploitation — low-effort attacks that automated tooling attempts against every site.',
    remediation:
      'Add a hardened header set (helmet for Express, or explicit response headers) including Content-Security-Policy, X-Content-Type-Options: nosniff, and frame protections; verify with a response-header scan.',
  },
  'VERBOSE-ERRORS': {
    title: 'Verbose error output leaks stack traces / internals',
    severity: 'medium',
    cwe: 'CWE-209',
    impact:
      'Stack traces and raw queries hand attackers a map of the codebase — file paths, library versions, table and column names — dramatically shortening the time needed to craft a working exploit against the other flaws present.',
    remediation:
      'Return generic error messages to clients; log full detail server-side only. Ensure NODE_ENV=production error handling is enforced and covered by a test that forces an exception.',
  },
};

/* ------------------------------ semver utils ------------------------------ */

function parseVer(v) {
  const m = String(v).match(/(\d+)\.(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}
function cmpVer(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}
/** Does `version` satisfy an advisory affected-range like "<4.17.21" or ">=6.0.0 <6.3.1"? */
function inRange(version, range) {
  const v = parseVer(version);
  if (!v) return false;
  return range.trim().split(/\s+/).every((clause) => {
    const m = clause.match(/^(<=|>=|<|>|=)?(.+)$/);
    const target = parseVer(m[2]);
    if (!target) return false;
    const c = cmpVer(v, target);
    switch (m[1] || '=') {
      case '<': return c < 0;
      case '<=': return c <= 0;
      case '>': return c > 0;
      case '>=': return c >= 0;
      default: return c === 0;
    }
  });
}

/* ------------------------------ file walking ------------------------------ */

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts']);
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);

function walk(dir, out = { code: [], manifests: [] }) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(full, out);
    } else if (entry.name === 'package.json') {
      out.manifests.push(full);
    } else if (CODE_EXT.has(path.extname(entry.name))) {
      out.code.push(full);
    }
  }
  return out;
}

/** Blank out comments while preserving line numbers (crude heuristic stripper). */
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, ' '))
    .replace(/(^|[^:'"\\])\/\/.*$/gm, '$1');
}

/* --------------------------------- checks --------------------------------- */

function finding(ruleId, file, line, evidence, extra = {}) {
  const meta = RULE_META[ruleId] || extra.meta;
  return {
    ruleId,
    title: meta.title,
    severity: meta.severity,
    cwe: meta.cwe,
    ...(extra.cve ? { cve: extra.cve } : {}),
    ...(extra.package ? { package: extra.package, installedVersion: extra.installedVersion } : {}),
    file,
    line,
    evidence: String(evidence || '').trim().slice(0, 160),
    impact: meta.impact,
    remediation: meta.remediation,
  };
}

const SQL_VERB = /\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b/i;

function staticChecks(target, files) {
  const findings = [];
  let hasServer = null; // {file, line} of first server-looking file
  let hasHeaders = false;

  for (const file of files) {
    const rel = path.relative(target, file);
    const raw = fs.readFileSync(file, 'utf8');
    const src = stripComments(raw);
    const lines = src.split('\n');

    if (/helmet|Content-Security-Policy|X-Content-Type-Options/i.test(src)) hasHeaders = true;
    if (!hasServer) {
      const idx = lines.findIndex((l) => /createServer|\.listen\s*\(|express\s*\(/.test(l));
      if (idx >= 0) hasServer = { file: rel, line: idx + 1, text: lines[idx] };
    }

    lines.forEach((line, i) => {
      const lineNo = i + 1;
      // SQL injection: SQL text combined with concatenation or interpolation.
      if (SQL_VERB.test(line) && (line.includes('${') || /['"]\s*\+|\+\s*['"]/.test(line) || /\.query\s*\([^)]*\+/.test(line))) {
        findings.push(finding('SQLI-CONCAT', rel, lineNo, line));
      }
      // Dynamic code evaluation.
      if (/\beval\s*\(|new\s+Function\s*\(/.test(line)) {
        findings.push(finding('EVAL-USE', rel, lineNo, line));
      }
      // Weak hashing.
      if (/createHash\s*\(\s*['"](md5|sha1)['"]\s*\)/i.test(line)) {
        findings.push(finding('WEAK-CRYPTO', rel, lineNo, line));
      }
      // Hardcoded secrets: identifier assigned a string literal of real length.
      if (/(api[_-]?key|api[_-]?secret|secret|password|passwd|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9_\-./+]{8,}['"]/i.test(line)) {
        findings.push(finding('HARDCODED-SECRET', rel, lineNo, line.replace(/(['"])[A-Za-z0-9_\-./+]{4,}(['"])/, '$1••••••$2')));
      }
      // Verbose errors: stack trace exposure.
      if (/\.stack\b/.test(line)) {
        findings.push(finding('VERBOSE-ERRORS', rel, lineNo, line));
      }
    });
  }

  if (hasServer && !hasHeaders) {
    findings.push(finding('MISSING-SECURITY-HEADERS', hasServer.file, hasServer.line, hasServer.text));
  }
  return findings;
}

function dependencyChecks(target, manifests) {
  const findings = [];
  for (const manifestPath of manifests) {
    const rel = path.relative(target, manifestPath);
    const rawLines = fs.readFileSync(manifestPath, 'utf8').split('\n');
    let pkg;
    try { pkg = JSON.parse(rawLines.join('\n')); } catch { continue; }
    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
    for (const [name, spec] of Object.entries(deps)) {
      const version = (String(spec).match(/(\d+\.\d+\.\d+)/) || [])[1];
      if (!version) continue;
      for (const adv of ADVISORIES) {
        if (adv.package !== name || !inRange(version, adv.affected)) continue;
        const lineIdx = rawLines.findIndex((l) => l.includes(`"${name}"`));
        findings.push(
          finding(adv.id, rel, lineIdx + 1 || null, `"${name}": "${spec}"`, {
            cve: adv.cve,
            package: name,
            installedVersion: version,
            meta: {
              title: adv.title,
              severity: adv.severity,
              cwe: adv.cwe,
              impact: `This application pins ${name} ${version}, which is affected by ${adv.cve} (${adv.title}). Public technical details and exploit tooling exist for this vulnerability; internet-wide scanners actively probe for it. A known-vulnerable dependency converts an unknown risk into a scheduled one.`,
              remediation: `Upgrade ${name} to ${adv.fixedIn} or later, re-run the dependency audit, and add automated dependency monitoring (e.g. Dependabot/Renovate) so pinned versions cannot silently age into known-vulnerable releases.`,
            },
          })
        );
      }
    }
  }
  return findings;
}

/* --------------------------------- report --------------------------------- */

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function scanDirectory(targetDir) {
  const target = path.resolve(targetDir);
  if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
    throw new Error(`Target is not a directory: ${targetDir}`);
  }
  const { code, manifests } = walk(target);
  const findings = [...dependencyChecks(target, manifests), ...staticChecks(target, code)].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.ruleId.localeCompare(b.ruleId)
  );
  const bySeverity = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
  return {
    meta: {
      tool: 'legacy-vuln-lab scanner',
      version: '1.0.0',
      target,
      scannedAt: new Date().toISOString(),
      filesScanned: code.length,
      manifestsScanned: manifests.length,
      notice: 'Static assessment only. Findings are indicators for authorized review, not proof of exploitability in a deployed environment.',
    },
    summary: { totalFindings: findings.length, bySeverity },
    findings,
  };
}

function renderMarkdown(report) {
  const { meta, summary, findings } = report;
  const sev = (s) => s.toUpperCase();
  let md = `# Security Assessment Report\n\n`;
  md += `**Target:** \`${meta.target}\`  \n**Scanned:** ${meta.scannedAt}  \n**Files scanned:** ${meta.filesScanned} source files, ${meta.manifestsScanned} package manifest(s)  \n**Scanner:** ${meta.tool} v${meta.version}\n\n`;
  md += `> ${meta.notice}\n\n`;
  md += `## Executive summary\n\n${summary.totalFindings} finding(s): `;
  md += Object.entries(summary.bySeverity).map(([k, v]) => `${v} ${k}`).join(', ') || 'none';
  md += `.\n\n`;
  if (summary.bySeverity.critical) {
    md += `**Critical findings require immediate attention.** At least one issue class present in this codebase is sufficient, on its own, to compromise the application and the data it holds.\n\n`;
  }
  md += `## Findings\n\n`;
  findings.forEach((f, i) => {
    md += `### ${i + 1}. [${sev(f.severity)}] ${f.title}\n\n`;
    md += `- **Rule:** \`${f.ruleId}\`${f.cve ? ` · **CVE:** ${f.cve}` : ''} · **Class:** ${f.cwe}\n`;
    md += `- **Location:** \`${f.file}\`${f.line ? ` line ${f.line}` : ''}\n`;
    if (f.package) md += `- **Dependency:** ${f.package} ${f.installedVersion}\n`;
    md += `- **Evidence:** \`${f.evidence}\`\n`;
    md += `- **Business impact:** ${f.impact}\n`;
    md += `- **Remediation:** ${f.remediation}\n\n`;
  });
  md += `## Methodology\n\nDependency versions pinned in package manifests were compared against a bundled advisory fixture modeled on public CVE records. Source files were checked for high-risk patterns: SQL string construction, dynamic code evaluation, weak password hashing, hardcoded secrets, verbose error output, and missing HTTP security-header configuration. Static findings indicate where a flaw class is present; a qualified reviewer should confirm exploitability in context before remediation work is scheduled.\n`;
  return md;
}

/* ----------------------------------- CLI ----------------------------------- */

function main(argv) {
  const args = argv.slice(2);
  const target = args.find((a) => !a.startsWith('--'));
  const outIdx = args.indexOf('--out');
  if (!target) {
    console.error('Usage: node scanner/scan.js <target-dir> [--out <output-dir>]');
    console.error('Only scan systems you own or are explicitly authorized to assess.');
    process.exit(2);
  }
  const report = scanDirectory(target);
  const outDir = outIdx >= 0 ? path.resolve(args[outIdx + 1]) : path.join(process.cwd(), `assessment-${path.basename(path.resolve(target))}`);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'report.json'), JSON.stringify(report, null, 2));
  fs.writeFileSync(path.join(outDir, 'report.md'), renderMarkdown(report));
  console.log(`Scanned ${report.meta.filesScanned} files, ${report.meta.manifestsScanned} manifest(s).`);
  console.log(`Findings: ${report.summary.totalFindings} ${JSON.stringify(report.summary.bySeverity)}`);
  console.log(`Report written to ${outDir}/report.md and report.json`);
  return report;
}

if (require.main === module) main(process.argv);
module.exports = { scanDirectory, renderMarkdown, inRange };
