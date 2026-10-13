'use strict';
/*
 * Legacy Vulnerability Lab — test suite (plain Node, no framework).
 * Run: node tests/run-tests.js
 *
 * 1. The scanner must find exactly the flaws cataloged in demo-app/PLANTED-FLAWS.md.
 * 2. The exploit demo's localhost guard must reject every non-local target.
 * 3. The exploit demo must actually bypass the demo app's login (localhost only).
 */
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const { scanDirectory } = require(path.join(ROOT, 'scanner', 'scan.js'));
const { assertLocalhost, runExploit } = require(path.join(ROOT, 'exploit-demo', 'exploit.js'));

let passed = 0;
function ok(name, fn) {
  fn();
  passed++;
  console.log(`  ok - ${name}`);
}

async function main() {
  console.log('Scanner vs planted-flaws catalog');
  const catalog = fs.readFileSync(path.join(ROOT, 'demo-app', 'PLANTED-FLAWS.md'), 'utf8');
  const expected = JSON.parse(catalog.match(/```json\n([\s\S]*?)```/)[1]);
  const report = scanDirectory(path.join(ROOT, 'demo-app'));
  const byRule = {};
  for (const f of report.findings) byRule[f.ruleId] = (byRule[f.ruleId] || 0) + 1;

  ok(`total findings == ${expected.totalFindings}`, () =>
    assert.strictEqual(report.summary.totalFindings, expected.totalFindings));
  for (const [ruleId, count] of Object.entries(expected.byRule)) {
    ok(`${ruleId} x${count}`, () => assert.strictEqual(byRule[ruleId] || 0, count, `rule ${ruleId}`));
  }
  ok('no unexpected rules in findings', () =>
    assert.deepStrictEqual(Object.keys(byRule).sort(), Object.keys(expected.byRule).sort()));
  ok('every finding carries file, severity and remediation', () =>
    report.findings.forEach((f) => {
      assert.ok(f.file && f.severity && f.remediation && f.impact, JSON.stringify(f));
    }));
  ok('SQLi findings point at two distinct locations', () => {
    const locs = report.findings.filter((f) => f.ruleId === 'SQLI-CONCAT').map((f) => `${f.file}:${f.line}`);
    assert.strictEqual(new Set(locs).size, 2);
  });

  console.log('Exploit-demo localhost guard');
  for (const bad of ['example.com', '192.168.1.10', '10.0.0.5', '0.0.0.0', 'rimrock.org', '']) {
    ok(`rejects "${bad}"`, () => assert.throws(() => assertLocalhost(bad), /REFUSED/));
  }
  for (const good of ['localhost', '127.0.0.1', '::1']) {
    ok(`accepts "${good}"`, () => assert.strictEqual(assertLocalhost(good), good));
  }
  {
    const res = await new Promise((resolve) => {
      const child = spawn(process.execPath, [path.join(ROOT, 'exploit-demo', 'exploit.js'), '--host', 'example.com'], { stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (d) => (out += d));
      child.stderr.on('data', (d) => (out += d));
      child.on('close', (code) => resolve({ code, out }));
    });
    assert.strictEqual(res.code, 2, res.out);
    assert.match(res.out, /REFUSED/);
    passed++;
    console.log('  ok - CLI exit code 2 with REFUSED message for --host example.com');
  }

  console.log('Exploit demo end-to-end (bundled app, localhost)');
  const port = 3817;
  const child = spawn(process.execPath, [path.join(ROOT, 'demo-app', 'app.js')], {
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  try {
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('app start timeout')), 8000);
      child.stdout.on('data', (d) => { if (String(d).includes('listening')) { clearTimeout(t); resolve(); } });
    });
    const evidence = await runExploit({ host: '127.0.0.1', port });
    ok('baseline wrong-password login is rejected (401)', () =>
      assert.strictEqual(evidence.baseline.status, 401));
    ok('SQL injection bypasses login (HTTP 200, ok:true)', () =>
      assert.strictEqual(evidence.bypassSucceeded, true));
    ok('UNION extraction returns the admin MD5 hash', () =>
      assert.strictEqual(evidence.extractionSucceeded, true));
  } finally {
    child.kill('SIGTERM');
  }

  console.log(`\nAll ${passed} checks passed.`);
}

main().catch((err) => { console.error('\nTEST FAILURE:', err); process.exit(1); });
