'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { temporary } = require('./helpers.cjs');
const root = path.resolve(__dirname, '..');
const token = 'acme_demo_a9B2c7D4e1F8g3H6';

function example(name, args = [], flags = []) {
  const result = spawnSync(process.execPath, [...flags, path.join(root, 'examples', name), ...args], {
    cwd: root, encoding: 'utf8', env: process.env, timeout: 120_000,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  assert.ok(!result.stdout.includes(token), 'Example must never log raw demo credentials');
  return result.stdout.trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line));
}

test('quickstart, custom rules, archive and filesystem recipes execute with redacted reports', () => {
  const quick = example('quickstart.mjs');
  assert.deepEqual(quick.map(row => row.phase), ['text', 'buffer', 'file']);
  assert.ok(quick.every(row => row.findings.length === 1 && row.findings[0].secret === '[REDACTED]'));
  const custom = example('custom-rules.mjs');
  assert.equal(custom.at(-1).findings.length, 2);
  assert.ok(!JSON.stringify(custom).includes('acme_toml_a9B2c7D4e1F8g3H6'));
  const archive = example('archive-content.mjs');
  assert.equal(archive[0].input.repository, 'synthetic-demo');
  assert.equal(archive[0].findings.length, 1);
  const project = example('scan-project.mjs');
  assert.equal(project.length, 1);
  assert.equal(project[0].findings.length, 1);
});

test('project paths use built-in detectors and preserve input failures', () => {
  const directory = temporary();
  try {
    const file = path.join(directory, 'application configuration.env');
    const secret = 'postgres://user:a9B2c7D4e1F8g3H6@example.invalid/db';
    fs.writeFileSync(file, secret + '\n');
    const rows = example('scan-project.mjs', [file]);
    assert.equal(rows.length, 1);
    assert.ok(rows[0].findings.some(finding => finding.visible));
    assert.ok(!JSON.stringify(rows).includes(secret));
    const missing = spawnSync(process.execPath, [path.join(root, 'examples/scan-project.mjs'), path.join(directory, 'missing.env')], {
      cwd: root, encoding: 'utf8', env: process.env, timeout: 120_000,
    });
    assert.equal(missing.status, 1, missing.stderr || missing.error?.message);
    assert.equal(missing.stdout, '', 'A failed input must not become a clean report');
    assert.equal(JSON.parse(missing.stderr.trim()).code, 'ERR_KINGFISHER_INPUT');
    for (const roots of [[path.join(directory, 'missing.env'), file], [file, path.join(directory, 'missing.env')]]) {
      const mixed = spawnSync(process.execPath, [path.join(root, 'examples/scan-project.mjs'), ...roots], {
        cwd: root, encoding: 'utf8', env: process.env, timeout: 120_000,
      });
      assert.equal(mixed.status, 1, mixed.stderr || mixed.error?.message);
      assert.equal(JSON.parse(mixed.stderr.trim()).code, 'ERR_KINGFISHER_INPUT');
      if (roots[0] === file) assert.ok(JSON.parse(mixed.stdout.trim()).findings.some(finding => finding.visible));
      else assert.equal(mixed.stdout, '', 'Enumeration must stop at the failed root');
      assert.ok(!mixed.stdout.includes(secret));
    }
    fs.writeFileSync(path.join(directory, '.ignore'), '[z-a]\n');
    const recoverable = spawnSync(process.execPath, [path.join(root, 'examples/scan-project.mjs'), directory], {
      cwd: root, encoding: 'utf8', env: process.env, timeout: 120_000,
    });
    assert.equal(recoverable.status, 1, recoverable.stderr || recoverable.error?.message);
    assert.equal(JSON.parse(recoverable.stderr.trim()).warning, 'ignore_error');
    assert.ok(JSON.parse(recoverable.stdout.trim()).findings.some(finding => finding.visible));
  } finally { fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
});

test('the control recipe exposes cancellation and limit failures without turning them into clean scans', () => {
  const output = example('controlled-scan.mjs');
  assert.equal(output[0].code, 'ERR_KINGFISHER_CANCELLED');
  assert.equal(output[1].code, 'ERR_KINGFISHER_LIMIT');
  assert.deepEqual(output[2], { phase: 'completed', inputs: 2, findings: 0 });
});

test('the local workflow uses no mutations by default and explicitly revokes only mock state', () => {
  const readOnly = example('local-workflow.mjs');
  assert.equal(readOnly[1].results[0].outcome, 'verified_active');
  assert.deepEqual(readOnly.at(-1), { phase: 'summary', requests: { validation: 1, revocation: 0 }, active: true });
  const revoke = example('local-workflow.mjs', ['--confirm-demo-revoke']);
  assert.equal(revoke[2].result.revoked, true);
  assert.deepEqual(revoke.at(-1), { phase: 'summary', requests: { validation: 1, revocation: 1 }, active: false });
});

test('the TypeScript recipe runs using the public package exports', () => {
  const output = example('typed-scan.mts', [], ['--experimental-strip-types']);
  assert.equal(output[0].input.path, 'typed.env');
  assert.equal(output[0].findings.length, 1);
});

test('the real-provider recipe rejects unsupported flags and mutation without validation', () => {
  for (const flag of ['--confirm-revoke', '--analyze', '--unknown']) {
    const result = spawnSync(process.execPath, [path.join(root, 'examples/validate-revoke.cjs'), 'missing.yml', 'missing.env', flag], {
      cwd: root, encoding: 'utf8', env: process.env, timeout: 10_000,
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /require explicit --validate|Unknown workflow flag/);
    assert.equal(result.stdout, '');
  }
});

test('Git recipes scan all four scopes without changing the caller repository', () => {
  const directory = temporary();
  const repository = path.join(directory, 'repository with spaces');
  fs.mkdirSync(repository);
  const git = args => {
    const result = spawnSync('git', ['-C', repository, ...args], { encoding: 'utf8', env: process.env });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    return result.stdout;
  };
  try {
    git(['init']);
    git(['config', 'user.name', 'SDK example test']);
    git(['config', 'user.email', 'sdk-example@example.invalid']);
    // Synthetic commits must not inherit a user's signing-key requirements.
    git(['config', 'commit.gpgsign', 'false']);
    const file = path.join(repository, 'config.env');
    fs.writeFileSync(file, 'ordinary configuration\n');
    git(['add', 'config.env']);
    git(['commit', '-m', 'Initial example fixture']);
    fs.writeFileSync(file, 'postgres://user:a9B2c7D4e1F8g3H6@example.invalid/db\n');
    git(['add', 'config.env']);
    git(['commit', '-m', 'Synthetic credential fixture']);
    fs.writeFileSync(file, 'postgres://user:b8C3d6E5f2G7h4J9@example.invalid/db\n');
    git(['add', 'config.env']);
    const before = git(['status', '--porcelain=v1']);
    const head = git(['rev-parse', 'HEAD']);
    for (const mode of ['snapshot', 'history', 'diff', 'staged']) {
      const output = example('git-scopes.mjs', [repository, mode, ...(mode === 'diff' ? ['HEAD', 'HEAD~1'] : [])]);
      assert.ok(output.some(row => row.findings.length > 0), `Expected a synthetic finding in ${mode}`);
      assert.ok(!JSON.stringify(output).includes('a9B2c7D4e1F8g3H6'));
      assert.ok(!JSON.stringify(output).includes('b8C3d6E5f2G7h4J9'));
      if (mode === 'staged') assert.ok(output.every(row => row.input.staged === true));
    }
    assert.equal(git(['status', '--porcelain=v1']), before);
    assert.equal(git(['rev-parse', 'HEAD']), head);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});
