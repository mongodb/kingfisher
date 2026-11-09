import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { cp, link, mkdir, mkdtemp, open, readFile, rm, stat, writeFile, symlink } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { request } from 'node:http';
import { gzipSync } from 'node:zlib';
import { runInNewContext } from 'node:vm';
import { parseArgs } from '../src/args.mjs';
import { createAgent, pump } from '../src/agent.mjs';
import { runReport } from '../src/main.mjs';
import { Rules, Revoker } from '../src/sdk.mjs';
import { renderReport } from '../src/report.mjs';
import { startReportServer } from '../src/server.mjs';
import { dedupeEntries, errorForReport, writePrivateFile } from '../src/safety.mjs';
import { createFixture } from '../demo/fixture.mjs';
import { startMockProvider, TOKEN, RETIRED_TOKEN, USERNAME } from '../demo/mock-provider.mjs';

async function fixture(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-test-'));
  const mock = await startMockProvider();
  t.after(async () => {
    await mock.close();
    // Exact private directory from mkdtemp, after tests close all native owners.
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const git = await createFixture(directory, mock.url);
  const options = parseArgs([git.repository, '--rules', git.rules, '--no-builtins', '--no-serve', '--out', path.join(directory, 'report.html')]);
  return { directory, mock, ...git, options };
}
function fakeEntry() {
  return {
    id: 'synthetic-id', path: 'config.env', source: 'working-tree',
    finding: { ruleId: 'acme.example-token', ruleName: 'Synthetic demo', secret: '[REDACTED]', captures: {}, fingerprint: '18446744073709551615', confidence: 'high', entropy: 4.2, location: { line: 2, column: 1, startOffset: 1, endOffset: 25 }, blobId: 'synthetic-blob', isBase64Encoded: false },
    outcome: 'verified_active', httpStatus: 200, revocationReady: true, revocation: { status: 'none' },
  };
}
function fakeMeta() {
  return { root: '/synthetic', version: '1.0.0', startedAt: new Date(0), durationMs: 0, scanned: 1, rulesCount: 1, redact: true, validate: true, revokeEnabled: true, confidence: 'medium' };
}
function reportClientSource(html) {
  // Extract our fixed template's inline script for VM tests, not HTML sanitization.
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\b[^>]*>/gi)];
  assert.equal(scripts.length, 1, 'report must contain exactly its constant client script');
  return scripts[0][1];
}
async function live(t, revokeEntry, { enabled = true } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-http-test-'));
  const entry = fakeEntry();
  const server = await startReportServer({
    entries: [entry], meta: { ...fakeMeta(), revokeEnabled: enabled }, revokeEntry,
    outPath: path.join(directory, 'report.html'), auditPath: path.join(directory, 'revocations.jsonl'),
  });
  t.after(async () => { await server.close(); await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  const response = await fetch(server.url);
  const html = await response.text();
  const token = /name="kf-token" content="([^"]+)"/.exec(html)[1];
  async function post(body = { id: entry.id, confirm: true }, headers = {}) {
    return fetch(`${server.url}/api/revoke`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-kf-token': token, ...headers }, body: JSON.stringify(body) });
  }
  return { server, directory, entry, token, html, post, response };
}

test('defaults are redacted and offline; mutation needs an explicit independent flag', () => {
  const options = parseArgs(['.']);
  assert.equal(options.validate, false); assert.equal(options.revoke, false); assert.equal(options.redact, true);
  assert.equal(options.port, 0); assert.equal(options.gitignore, true); assert.equal(options.hidden, true);
  assert.throws(() => parseArgs(['.', '--enable-revoke']), /requires explicit/);
  assert.throws(() => parseArgs(['.', '--validate', '--enable-revoke', '--no-validate']), /requires explicit/);
  const optedIn = parseArgs(['.', '--validate', '--enable-revoke']);
  assert.equal(optedIn.validate, true); assert.equal(optedIn.revoke, true); assert.equal(optedIn.redact, true);
  assert.equal(parseArgs(['.', '--show-secrets', '--redact']).redact, true);
});

test('parser rejects ambiguity, missing values, unsupported flags and non-finite budgets', () => {
  for (const args of [['--jobs', '0'], ['--jobs=3.5'], ['--port', '65536'], ['--rules'], ['--validate=yes'], ['--no-builtins'], ['--max-file-size', '99999999999999999999GiB'], ['--shards', '4']]) {
    assert.throws(() => parseArgs(['.', ...args]));
  }
  assert.equal(parseArgs(['.', '--max-file-size=1MiB']).maxFileSize, 1024 ** 2);
  assert.equal(parseArgs(['.', '--max-file-size=0']).maxFileSize, null);
  assert.equal(parseArgs(['.', '--git-history-max-inputs=0']).gitHistoryMaxInputs, 0);
  for (const args of [['first', '--root', 'second'], ['--root', 'first', 'second'], ['--root', 'first', '--root', 'second']]) {
    assert.throws(() => parseArgs(args), /directory/);
  }
  assert.equal(parseArgs(['--root', 'only']).root, path.resolve('only'));
});

test('prototype-named directories stay positional and option tables ignore inherited keys', () => {
  for (const name of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
    assert.equal(parseArgs([name]).root, path.resolve(name));
    assert.throws(() => parseArgs([name, 'extra']), /Unexpected directory/);
  }
  Object.defineProperty(Object.prototype, '--inherited-test-option', { value: ['quiet', true], configurable: true });
  try { assert.throws(() => parseArgs(['.', '--inherited-test-option']), /Unknown option/); }
  finally { delete Object.prototype['--inherited-test-option']; }
  assert.equal(parseArgs(['.', '--validate', '--enable-revoke', '--audit', 'new audit.jsonl']).audit, path.resolve('new audit.jsonl'));
  for (const args of [['--audit', 'a.jsonl'], ['--validate', '--audit', 'a.jsonl'], ['--validate', '--enable-revoke', '--no-serve', '--audit', 'a.jsonl']]) {
    assert.throws(() => parseArgs(['.', ...args]), /--audit requires/);
  }
});

test('outcome summary counts not-attempted explicitly, preserving other native outcomes', () => {
  const outcomes = ['verified_active', 'verified_inactive', 'unavailable', 'assumed', 'not_attempted', 'skipped', 'locally_derived', 'invalid_material'];
  const entries = outcomes.map((outcome, id) => ({ ...fakeEntry(), id: String(id), outcome }));
  const html = renderReport({ entries, meta: fakeMeta() });
  const counts = Object.fromEntries([...html.matchAll(/class="value">(\d+)<\/div><div class="label">([^<]+)<\/div>/g)].map(([, count, label]) => [label, Number(count)]));
  assert.equal(counts.Verified, 2); assert.equal(counts.Unavailable, 1); assert.equal(counts.Assumed, 1);
  assert.equal(counts['Not attempted'], 1); assert.equal(counts.Other, 3);
  assert.equal(counts.Verified + counts.Unavailable + counts.Assumed + counts['Not attempted'] + counts.Other, entries.length);
  assert.match(html, /<option value="unavailable">Unavailable<\/option>/);
  assert.match(html, /<option value="assumed">Assumed<\/option>/);
});

test('report client test extraction handles case-insensitive tags and closing-tag attributes', () => {
  const html = renderReport({ entries: [], meta: fakeMeta() });
  const expected = reportClientSource(html);
  for (const tag of ['SCRIPT', 'ScRiPt']) {
    const variant = html.replace('<script>', `<${tag} data-test="fixed">`).replace('</script>', `</${tag} ignored="yes">`);
    assert.equal(reportClientSource(variant), expected);
  }
});

test('report client distinguishes empty scans and filters native outcome categories accurately', () => {
  function client(rows) {
    const elements = new Map();
    const document = {
      querySelector: () => null,
      querySelectorAll: (selector) => selector === 'tr.finding' ? rows : [],
      addEventListener() {},
      getElementById(id) {
        if (id.startsWith('details-')) return null;
        if (!elements.has(id)) elements.set(id, {
          value: id === 'outcome-filter' ? 'all' : '', checked: false, hidden: true,
          events: {}, addEventListener(event, callback) { this.events[event] = callback; },
        });
        return elements.get(id);
      },
    };
    const html = renderReport({ entries: [], meta: fakeMeta() });
    runInNewContext(reportClientSource(html), { document });
    return elements;
  }
  const empty = client([]);
  assert.equal(empty.get('empty-state').hidden, true);
  const row = { dataset: { id: 'one', search: 'synthetic', outcome: 'not_attempted' }, querySelector: () => null };
  const populated = client([row]);
  assert.equal(populated.get('empty-state').hidden, true);
  assert.equal(populated.get('visible-count').textContent, '1 of 1 finding');
  populated.get('search').value = 'no match';
  populated.get('search').events.input();
  assert.equal(populated.get('empty-state').hidden, false);
  assert.equal(row.hidden, true);

  const outcomes = ['verified_active', 'verified_inactive', 'unavailable', 'assumed', 'not_attempted', 'skipped', 'locally_derived', 'invalid_material'];
  const rows = outcomes.map((outcome, id) => ({ dataset: { id: String(id), search: 'synthetic', outcome }, querySelector: () => null }));
  const filtered = client(rows);
  for (const [value, expected] of [
    ['all', outcomes], ['other', ['skipped', 'locally_derived', 'invalid_material']],
    ...outcomes.slice(0, 5).map((outcome) => [outcome, [outcome]]),
  ]) {
    filtered.get('outcome-filter').value = value;
    filtered.get('outcome-filter').events.change();
    assert.deepEqual(rows.filter((row) => !row.hidden).map((row) => row.dataset.outcome), expected);
    assert.equal(filtered.get('visible-count').textContent, `${expected.length} of 8 findings`);
  }
});

test('not-confirmed revocation uses warning styling in live updates and snapshots', () => {
  const entry = { ...fakeEntry(), revocationReady: false, revocation: { status: 'not_confirmed', httpStatus: 400 } };
  const html = renderReport({ entries: [entry], meta: fakeMeta() });
  assert.match(html, /class="pill warn"[^>]*>Not confirmed<\/span>/);
  const source = /  function updateRow\(row, data\) \{[\s\S]*?\n  \}/.exec(html)[0];
  const pills = [];
  const updateRow = runInNewContext(`(${source})`, {
    document: { createElement: () => ({}) }, updateRevocableCount() {},
  });
  const row = { dataset: {}, querySelector: () => ({ appendChild: (pill) => pills.push(pill) }) };
  updateRow(row, entry.revocation);
  assert.equal(row.dataset.status, 'not_confirmed'); assert.equal(row.dataset.revocable, '0');
  assert.equal(pills[0].className, 'pill warn'); assert.equal(pills[0].textContent, 'Not confirmed');
});

test('single-input report pluralizes counts and describes history without truncation scaffolding', () => {
  const html = renderReport({ entries: [fakeEntry()], meta: { ...fakeMeta(), gitHistory: { enabled: true }, scannedGitHistory: 1 } });
  assert.match(html, /1 file \+ 1 historical file version/);
  assert.match(html, /1 finding · 1 detection rule/);
  assert.match(html, /1 historical file version scanned/);
  assert.ok(!html.includes('--git-history-commits'));
  assert.ok(!html.includes('History scope:'));
});

test('Git fixture isolates inherited environment without changing a caller index', async (t) => {
  const f = await fixture(t);
  const directory = path.join(f.directory, 'isolated-git');
  const callerIndex = path.join(f.directory, 'caller-index');
  await mkdir(directory);
  await writeFile(callerIndex, 'owned sentinel: do not change\n');
  // Control the child environment without mutating this test runner's globals.
  // Mixed-case names are operational environment variables on Windows too.
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toUpperCase().startsWith('GIT_')));
  Object.assign(env, { gIt_DiR: path.join(f.directory, 'not-a-repository'), GIT_INDEX_FILE: callerIndex });
  delete env.NODE_TEST_CONTEXT;
  const moduleUrl = new URL('../demo/fixture.mjs', import.meta.url).href;
  const code = `const { createFixture } = await import(${JSON.stringify(moduleUrl)});
    console.log(JSON.stringify(await createFixture(${JSON.stringify(directory)}, ${JSON.stringify(f.mock.url)})));`;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], {
    encoding: 'utf8', env, timeout: 30_000,
  });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
  const created = JSON.parse(result.stdout);
  assert.equal(created.repository, path.join(directory, 'repository'));
  assert.ok((await stat(path.join(created.repository, '.git'))).isDirectory());
  assert.equal(await readFile(callerIndex, 'utf8'), 'owned sentinel: do not change\n');
});

test('CLI entrypoints run through owned directory symlinks or Windows junctions', async (t) => {
  const f = await fixture(t);
  const target = path.join(f.directory, 'owned-app');
  const alias = path.join(f.directory, 'linked-app');
  await mkdir(target);
  await cp(new URL('../src/', import.meta.url), path.join(target, 'src'), { recursive: true });
  await cp(new URL('../demo/', import.meta.url), path.join(target, 'demo'), { recursive: true });
  // Directory junctions do not require Windows Developer Mode or admin rights.
  // Both the copied target and alias live under this test's private temp root.
  await symlink(target, alias, process.platform === 'win32' ? 'junction' : 'dir');
  const sdk = process.env.KINGFISHER_WORKBENCH_SDK ?? fileURLToPath(import.meta.resolve('kingfisher-secret-scanner'));
  const env = { ...process.env, KINGFISHER_WORKBENCH_SDK: sdk };
  delete env.NODE_TEST_CONTEXT; // A nested CLI process is not a test-runner child.
  const invoke = (entry, args) => spawnSync(process.execPath, [path.join(alias, entry), ...args], {
    encoding: 'utf8', env, timeout: 30_000,
  });
  const help = invoke('src/main.mjs', ['--help']);
  assert.equal(help.status, 0, help.stderr);
  assert.match(help.stdout, /^Kingfisher Workbench —/);
  assert.match(help.stdout, /Usage:/i);
  const html = path.join(f.directory, 'symlink-report.html');
  const json = path.join(f.directory, 'symlink-report.json');
  const scan = invoke('src/main.mjs', [f.repository, '--rules', f.rules, '--no-builtins', '--no-git-history', '--no-serve', '--out', html, '--json', json]);
  assert.equal(scan.status, 0, scan.stderr);
  assert.match(await readFile(html, 'utf8'), /Kingfisher Workbench/);
  const exported = await readFile(json, 'utf8');
  assert.equal(JSON.parse(exported).entries.length, 1); assert.ok(!exported.includes(TOKEN));
  const demo = invoke('demo/run.mjs', ['--invalid-option']);
  assert.equal(demo.status, 1); assert.match(demo.stderr, /Demo accepts only --open/);
});

test('coordinator rejects aliased exports before loading rules, scanning or writing', async (t) => {
  const f = await fixture(t);
  const actual = path.join(f.directory, 'reports'), alias = path.join(f.directory, 'linked-reports');
  await mkdir(actual);
  await symlink(actual, alias, process.platform === 'win32' ? 'junction' : 'dir');
  const prior = path.join(actual, 'prior.html'), hardlink = path.join(actual, 'prior.json');
  await writeFile(prior, 'prior report\n'); await link(prior, hardlink);
  for (const [out, json] of [
    [path.join(actual, 'missing', 'nested', 'report.html'), path.join(alias, 'missing', 'nested', 'report.html')],
    [path.join(actual, 'report.html'), path.join(actual, 'REPORT.HTML')],
    [prior, hardlink],
  ]) {
    await assert.rejects(runReport({
      ...f.options, out, json, quiet: true, validate: true,
      rules: path.join(f.directory, 'missing-rules.yml'),
    }), { code: 'ERR_WORKBENCH_OUTPUT_COLLISION' });
  }
  assert.equal(f.mock.state.validationRequests, 0); assert.equal(f.mock.state.revokeRequests, 0);
  for (const file of [prior, hardlink]) assert.equal(await readFile(file, 'utf8'), 'prior report\n');
  await assert.rejects(stat(path.join(actual, 'missing')), { code: 'ENOENT' });
  await assert.rejects(stat(path.join(actual, 'report.html')), { code: 'ENOENT' });
});

test('redacted input errors are actionable without exposing arbitrary error messages', async (t) => {
  const f = await fixture(t);
  for (const [options, expected] of [
    [{ ...f.options, root: null }, /Select an existing directory/],
    [{ ...f.options, root: '' }, /Select an existing directory/],
    [{ ...f.options, root: path.join(f.directory, `missing-${TOKEN}`) }, /Select an existing directory/],
    [{ ...f.options, root: f.rules }, /Select an existing directory/],
    [{ ...f.options, json: f.options.out }, /outputs must be different files/],
    [{ ...f.options, revoke: true }, /Revocation requires explicit --validate/],
  ]) {
    await assert.rejects(runReport(options), (error) => {
      const text = errorForReport(error);
      assert.match(text, expected); assert.ok(!text.includes(TOKEN));
      return true;
    });
  }
  await assert.rejects(writePrivateFile(f.repository, 'do not write'), (error) => {
    assert.match(errorForReport(error), /Refusing to replace a non-regular report output/);
    return true;
  });
  const arbitrary = Object.assign(new Error(`provider echoed ${TOKEN}`), { safeToReport: true });
  assert.equal(errorForReport(arbitrary), 'operation_failed');
  arbitrary.code = 'ERR_WORKBENCH_INVALID_ROOT';
  assert.equal(errorForReport(arbitrary), arbitrary.code);
  assert.equal(errorForReport(arbitrary, false), arbitrary.message);
  // Local filesystem failures keep a fixed code and syscall, never message or path.
  const denied = Object.assign(new Error(`EACCES: open '/home/u/${TOKEN}/report.html'`),
    { code: 'EACCES', syscall: 'open', path: `/home/u/${TOKEN}/report.html` });
  assert.equal(errorForReport(denied), 'EACCES (open)');
  assert.equal(errorForReport(Object.assign(new Error('x'), { code: 'ENOSPC', syscall: `w${TOKEN}` })), 'ENOSPC');
  assert.equal(errorForReport(Object.assign(new Error('x'), { code: 'ECONNRESET' })), 'operation_failed');
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const cli = spawnSync(process.execPath, [fileURLToPath(new URL('../src/main.mjs', import.meta.url)), path.join(f.directory, `missing-${TOKEN}`), '--no-serve'], {
    encoding: 'utf8', env, timeout: 30_000,
  });
  assert.equal(cli.status, 1, cli.stderr);
  assert.match(cli.stderr, /ERR_WORKBENCH_INVALID_ROOT: Select an existing directory/);
  assert.ok(!cli.stderr.includes(TOKEN));
  assert.equal(f.mock.state.validationRequests, 0);
});

test('bounded pump preserves first handler failure and closes the iterator', async () => {
  let active = 0, peak = 0, finalized = false;
  const original = Object.assign(new Error('secret-bearing provider message'), { code: 'ERR_KINGFISHER_TIMEOUT' });
  async function* inputs() { try { for (let i = 0; i < 10; i++) yield i; } finally { finalized = true; } }
  await assert.rejects(pump(inputs(), 2, async (item) => {
    active++; peak = Math.max(peak, active);
    try { await Promise.resolve(); if (item === 2) throw original; } finally { active--; }
  }), (error) => error === original);
  assert.equal(finalized, true); assert.equal(active, 0); assert.ok(peak <= 2);
  assert.equal(errorForReport(original), 'ERR_KINGFISHER_TIMEOUT');
  assert.equal(errorForReport(original, false), original.message);
});

test('aborted pumping never returns empty success', async () => {
  const controller = new AbortController(); controller.abort();
  async function* inputs() { yield 1; }
  await assert.rejects(pump(inputs(), 1, () => assert.fail('must not submit'), controller.signal), { name: 'AbortError' });
});

test('report HTML escapes untrusted source fields; snapshot strips even a supplied token', () => {
  const expectedClient = reportClientSource(renderReport({ entries: [], meta: fakeMeta() }));
  for (const tag of ['script', 'SCRIPT', 'ScRiPt']) {
    const entry = fakeEntry();
    entry.path = `</${tag} ignored="yes"><${tag}>globalThis.pwned=1</${tag}>`;
    entry.finding.ruleName = '<img src=x onerror=alert(1)>';
    const html = renderReport({ entries: [entry], meta: fakeMeta(), token: 'sensitive-session-token', interactive: false });
    assert.match(html, /<title>Kingfisher Workbench — /);
    assert.match(html, /<h1>Kingfisher Workbench<\/h1>/);
    assert.ok(html.includes(`&lt;${tag}&gt;globalThis.pwned=1&lt;/${tag}&gt;`));
    assert.ok(!html.includes(`<${tag}>globalThis.pwned`));
    assert.equal(reportClientSource(html), expectedClient);
    assert.ok(!html.includes('sensitive-session-token'));
    assert.ok(!html.includes('class="btn danger btn-revoke"'));
    assert.ok(html.includes('18446744073709551615'));
  }
});

test('deduplication prefers a verified native context; no-dedup remains a coordinator choice', () => {
  const first = { dedupeKey: 'private', outcome: 'skipped' };
  const second = { dedupeKey: 'private', outcome: 'verified_active' };
  assert.deepEqual(dedupeEntries([first, second]), [second]);
});

test('no-serve stops an active TTY progress line before printing the snapshot path', async (t) => {
  const f = await fixture(t);
  const chunks = [];
  const stream = process.stdout;
  const tty = Object.getOwnPropertyDescriptor(stream, 'isTTY');
  const interval = globalThis.setInterval;
  Object.defineProperty(stream, 'isTTY', { value: true, configurable: true });
  try {
    t.mock.method(stream, 'write', (chunk) => { chunks.push(String(chunk)); return true; });
    t.mock.method(globalThis, 'setInterval', (callback, delay, ...args) => {
      const timer = interval(callback, delay, ...args);
      // Force a real live line even when the tiny native scan finishes before a tick.
      if (delay === 200) callback(...args);
      return timer;
    });
    await runReport({ ...f.options, progress: true, quiet: false, gitHistory: false });
  } finally {
    t.mock.restoreAll();
    if (tty) Object.defineProperty(stream, 'isTTY', tty);
    else delete stream.isTTY;
  }
  const snapshot = chunks.findIndex((chunk) => chunk.startsWith('[report] snapshot:'));
  assert.ok(snapshot > 0);
  assert.ok(chunks.slice(0, snapshot).some((chunk) => chunk.startsWith('\r') && !/^\r +\r$/.test(chunk)), 'regression must exercise an active live line');
  assert.match(chunks[snapshot - 1], /^\r +\r$/, 'clear the live line before printing');
  assert.ok(chunks.slice(snapshot + 1).every((chunk) => !chunk.includes('\r')), 'cleanup must not clear the final location');
});

test('offline tree/history pipeline retains provenance and leaks no credential fields', async (t) => {
  const f = await fixture(t);
  f.options.json = path.join(f.directory, 'scan.json');
  const report = await runReport(f.options);
  assert.equal(f.mock.state.validationRequests, 0); assert.equal(f.mock.state.revokeRequests, 0);
  assert.equal(report.entries.length, 2);
  assert.ok(report.entries.every((entry) => entry.outcome === 'not_attempted' && !entry.revocationReady));
  const historical = report.entries.find((entry) => entry.source === 'history');
  assert.ok(historical); assert.equal(historical.commit.id, f.oldCommit);
  assert.equal(historical.input.repository, f.repository);
  assert.ok(historical.input.originIds.includes(f.oldCommit));
  assert.equal(Buffer.from(historical.rawPathBase64, 'base64').toString(), 'config.env');
  assert.equal(typeof historical.finding.fingerprint, 'string');
  for (const file of [f.options.out, f.options.json]) {
    const text = await readFile(file, 'utf8');
    assert.ok(!text.includes(TOKEN)); assert.ok(!text.includes(RETIRED_TOKEN)); assert.ok(!text.includes(USERNAME));
    assert.ok(!text.includes('dedupeKey'));
    if (process.platform !== 'win32') assert.equal((await stat(file)).mode & 0o777, 0o600);
  }
});

test('audit paths cannot collide with exports, and static runs leave existing audits untouched', async (t) => {
  const f = await fixture(t);
  const json = path.join(f.directory, 'report.json');
  for (const audit of [f.options.out, json]) {
    await assert.rejects(runReport({ ...f.options, serve: true, validate: true, revoke: true, json, audit }), /different files/);
  }
  assert.equal(f.mock.state.validationRequests, 0);
  const audit = path.join(f.directory, 'existing-audit.jsonl');
  await writeFile(audit, 'prior session\n', { mode: 0o644 });
  const before = await stat(audit);
  await runReport({ ...f.options, validate: true, revoke: true, allowInternalIps: true, audit });
  assert.equal(await readFile(audit, 'utf8'), 'prior session\n');
  assert.equal((await stat(audit)).mode, before.mode);
  assert.equal(f.mock.state.revokeRequests, 0);
});

test('the source agent excludes the selected audit path, not an assumed adjacent filename', async (t) => {
  const f = await fixture(t);
  const audit = path.join(f.repository, 'custom-audit.env');
  await cp(path.join(f.repository, 'config.env'), audit);
  const agent = await createAgent({ options: { ...f.options, audit } });
  try {
    await agent.run();
    assert.equal(agent.entries.length, 1);
    assert.ok(agent.entries.every((entry) => entry.path !== audit));
    assert.ok(agent.counters.skipped >= 1);
  } finally { await agent.close(); }
});

test('tree exclusions are root-relative even below src and node_modules ancestors', async (t) => {
  const f = await fixture(t);
  const root = path.join(f.directory, 'src', 'node_modules', 'project');
  await mkdir(path.join(root, 'src'), { recursive: true });
  await mkdir(path.join(root, 'node_modules'), { recursive: true });
  for (const relative of ['keep.env', path.join('src', 'excluded.env'), path.join('node_modules', 'dependency.env')]) {
    await cp(path.join(f.repository, 'config.env'), path.join(root, relative));
  }
  const report = await runReport({ ...f.options, root, exclude: ['src'], gitHistory: false });
  assert.equal(report.entries.length, 1);
  assert.equal(path.relative(root, report.entries[0].path), 'keep.env');
  assert.equal(report.meta.scanned, 1); assert.equal(report.meta.skipped, 2);
  assert.match(await readFile(f.options.out, 'utf8'), /2 inputs skipped by Workbench exclusions/);
  assert.equal(f.mock.state.validationRequests, 0);
});

test('warning detail caps do not undercount the total in metadata or HTML', async (t) => {
  const f = await fixture(t);
  const root = path.join(f.directory, 'malformed-content');
  await mkdir(root);
  for (let index = 0; index < 205; index++) await writeFile(path.join(root, `${index}.pyc`), 'invalid bytecode');
  const report = await runReport({ ...f.options, root, gitHistory: false });
  assert.equal(report.meta.warningCount, 205); assert.equal(report.meta.warnings.length, 200);
  const html = await readFile(f.options.out, 'utf8');
  assert.match(html, /205 input warnings/);
  assert.match(html, /Showing 200 of 205 warnings/);
  assert.equal((html.match(/content_extraction_failed/g) ?? []).length, 200);
});

test('raw fields require --show-secrets; no-dedup preserves separate source occurrences', async (t) => {
  const f = await fixture(t);
  f.options.redact = false; f.options.dedup = false;
  const report = await runReport(f.options);
  assert.equal(report.entries.length, 3);
  assert.ok((await readFile(f.options.out, 'utf8')).includes(TOKEN));
  assert.equal(f.mock.state.validationRequests, 0);
});

test('invisible native helper survives validation and original snapshot authorizes one revoke', async (t) => {
  const f = await fixture(t);
  Object.assign(f.options, { validate: true, revoke: true, allowInternalIps: true });
  const agent = await createAgent({ options: f.options });
  try {
    await agent.run();
    assert.equal(agent.entries.length, 1);
    const entry = agent.entries[0];
    assert.equal(entry.outcome, 'verified_active'); assert.equal(entry.revocationReady, true);
    assert.equal(entry.finding.ruleId, 'acme.example-token');
    assert.equal(f.mock.state.validationRequests, 1); assert.equal(f.mock.state.revokeRequests, 0);
    const rules = await Rules.load({ paths: [f.rules], builtins: false });
    const revoker = await Revoker.create({ rules });
    try { await assert.rejects(revoker.revoke(JSON.parse(JSON.stringify(entry)), { confirm: true }), /original ValidationResult/); }
    finally { await revoker.close(); }
    const result = await agent.revoke(entry.id);
    assert.equal(result.status, 'revoked'); assert.equal(result.httpStatus, 204);
    assert.equal(f.mock.state.active, false); assert.equal(f.mock.state.revokeRequests, 1);
    await assert.rejects(agent.revoke(entry.id), /No retained/);
    assert.equal(f.mock.state.revokeRequests, 1);
  } finally { await agent.close(); }
});

test('default medium Workbench compilation excludes the low generic API-key detector', async (t) => {
  const f = await fixture(t);
  const selected = await Rules.load({ paths: [f.rules], builtins: true, confidence: 'medium' });
  const low = await Rules.load({ paths: [f.rules], builtins: true, confidence: 'low' });
  assert.ok(!selected.metadata().some((rule) => rule.id.endsWith('.generic-api-key')));
  assert.ok(low.metadata().some((rule) => rule.id.endsWith('.generic-api-key')));
  const agent = await createAgent({ options: { ...f.options, builtins: true } });
  try {
    assert.equal(agent.rulesCount, selected.length);
    assert.ok(agent.rulesCount < low.length);
    await agent.run();
    assert.ok(agent.entries.every((entry) => !entry.finding.ruleId.endsWith('.generic-api-key')));
    assert.equal(f.mock.state.validationRequests, 0);
  } finally { await agent.close(); }
});

test('validation keeps low-confidence helper context without authorizing helper or unrelated requests', async (t) => {
  const f = await fixture(t);
  const validation = `    validation:
      type: Http
      content:
        request:
          method: GET
          url: '${f.mock.url}/identity'
          headers:
            Authorization: 'Bearer {{ TOKEN }}'
          response_matcher:
            - type: StatusMatch
              status: [200]
`;
  const yaml = (await readFile(f.rules, 'utf8'))
    .replace('name: Acme demo token (local mock)', 'name: Acme demo token (local mock)\n    confidence: high')
    .replace('visible: false', 'visible: true\n    confidence: low') + validation + `
  - id: acme.unrelated-low
    name: Unrelated synthetic credential
    confidence: low
    pattern: '(acme_low_[A-Za-z0-9]{16})'
    min_entropy: 0
` + validation;
  await writeFile(f.rules, yaml);
  const config = path.join(f.repository, 'config.env');
  await writeFile(config, (await readFile(config, 'utf8')) + '\nACME_LOW=acme_low_a9B2c7D4e1F8g3H6\n');
  Object.assign(f.options, { validate: true, confidence: 'high', allowInternalIps: true });
  const agent = await createAgent({ options: f.options });
  try {
    await agent.run();
    assert.equal(agent.rulesCount, 2, 'compile the primary and its helper, not the unrelated low rule');
    assert.equal(agent.entries.length, 1);
    assert.equal(agent.entries[0].finding.ruleId, 'acme.example-token');
    assert.equal(agent.entries[0].outcome, 'verified_active', 'the original helper still supplies USERNAME');
    assert.equal(f.mock.state.validationRequests, 1, 'only the high-confidence primary may send a request');
  } finally { await agent.close(); }
  // Lowering the threshold explicitly authorizes both additional visible rules.
  const low = await createAgent({ options: { ...f.options, confidence: 'low' } });
  try {
    await low.run();
    assert.equal(low.rulesCount, 3); assert.equal(low.entries.length, 3);
    assert.equal(f.mock.state.validationRequests, 4);
  } finally { await low.close(); }
});

test('archive transforms retain paths and fail budgets instead of scanning partial/raw fallback', async (t) => {
  const f = await fixture(t);
  const archive = path.join(f.repository, 'export.env.gz');
  await writeFile(archive, gzipSync(`ACME_USER=${USERNAME}\nACME_TOKEN=${TOKEN}\n`));
  f.options.extract = true;
  const agent = await createAgent({ options: f.options });
  try {
    await agent.run();
    assert.ok(agent.entries.some((entry) => entry.path.includes('export.env.gz!')));
    assert.equal(f.mock.state.validationRequests, 0);
  } finally { await agent.close(); }
  f.options.maxExtractedSize = 1;
  const limited = await createAgent({ options: f.options });
  try {
    await assert.rejects(limited.run(), (error) => error.code === 'ERR_KINGFISHER_LIMIT');
    assert.equal(limited.entries.length, 0);
  } finally { await limited.close(); }
});

test('native Git budget error is fatal, never a truncated successful report', async (t) => {
  const f = await fixture(t);
  f.options.gitHistoryMaxCommits = 1;
  const agent = await createAgent({ options: f.options, target: 'history' });
  try {
    await assert.rejects(agent.run(), (error) => Boolean(error.code) && /budget|max_commits/i.test(error.message));
    assert.equal(agent.entries.length, 0);
  } finally { await agent.close(); }
});

test('HTTP mutation rejects cross-origin, missing token, missing confirmation and invalid Host', async (t) => {
  let calls = 0;
  const liveReport = await live(t, async () => { calls++; return { status: 'revoked', httpStatus: 204 }; });
  const { server, post, token, entry } = liveReport;
  assert.equal(liveReport.response.headers.get('cache-control'), 'no-store');
  assert.ok(liveReport.response.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
  assert.equal((await post(undefined, { 'x-kf-token': 'wrong' })).status, 403);
  assert.equal((await post(undefined, { origin: 'https://attacker.invalid' })).status, 403);
  assert.equal((await post({ id: entry.id })).status, 400);
  assert.equal((await post({ id: entry.id, confirm: 'true' })).status, 400);
  assert.equal((await post(null)).status, 400);
  assert.equal((await post(undefined, { 'content-type': 'text/plain' })).status, 415);
  const hostStatus = await new Promise((resolve, reject) => {
    const req = request(server.url, { headers: { Host: 'attacker.invalid' } }, (res) => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject); req.end();
  });
  assert.equal(hostStatus, 421); assert.equal(calls, 0);
  assert.equal((await post()).status, 200); assert.equal(calls, 1);
  assert.equal((await post()).status, 409); assert.equal(calls, 1);
  const snapshot = await readFile(path.join(liveReport.directory, 'report.html'), 'utf8');
  const audit = await readFile(path.join(liveReport.directory, 'revocations.jsonl'), 'utf8');
  assert.ok(!snapshot.includes(token)); assert.ok(!audit.includes(token)); assert.ok(audit.includes('attempt_started'));
});

test('concurrent revocations spend a capability once; unknown outcome cannot be retried', async (t) => {
  let calls = 0;
  let release, entered;
  const blocked = new Promise((resolve) => { release = resolve; });
  const submitted = new Promise((resolve) => { entered = resolve; });
  const { post, entry } = await live(t, async () => { calls++; entered(); await blocked; return { status: 'failed', outcomeUnknown: true, code: 'ERR_KINGFISHER_TIMEOUT', error: `provider echoed ${TOKEN}` }; });
  const first = post();
  try {
    // Observe the actual callback, then keep it blocked until the overlapping
    // request is rejected. Releasing immediately after fetch() proves nothing.
    await submitted;
    assert.equal(entry.revocation.status, 'revoking');
    const second = await post();
    assert.equal(second.status, 409);
    assert.equal(calls, 1); assert.equal(entry.revocation.status, 'revoking');
  } finally { release(); }
  const successful = await first;
  assert.equal(successful.status, 200);
  const body = await successful.json();
  assert.equal(body.status, 'unknown'); assert.equal(body.outcomeUnknown, true);
  assert.equal(body.code, 'ERR_KINGFISHER_TIMEOUT'); assert.ok(!JSON.stringify(body).includes(TOKEN));
  assert.equal(entry.revocationReady, false); assert.equal(calls, 1); assert.equal((await post()).status, 409);
});

test('snapshot writes are queued and render the latest state when they run', async (t) => {
  const { server, directory, entry } = await live(t, async () => assert.fail('no provider request'));
  const snapshot = () => readFile(path.join(directory, 'report.html'), 'utf8');
  entry.revocation = { status: 'revoking', at: new Date(0).toISOString() };
  const first = server.writeSnapshot();
  // A render captured at call time would persist "Revoking…" here.
  entry.revocation = { status: 'revoked', at: new Date(0).toISOString(), httpStatus: 200 };
  await first;
  assert.match(await snapshot(), /pill ok">Revoked/);
  // Overlapping writes complete in order, so the final file is the newest state.
  entry.revocation = { status: 'revoking', at: new Date(0).toISOString() };
  const writes = [server.writeSnapshot(), server.writeSnapshot()];
  entry.revocation = { status: 'revoked', at: new Date(0).toISOString(), httpStatus: 200 };
  writes.push(server.writeSnapshot());
  await Promise.all(writes);
  const final = await snapshot();
  assert.match(final, /pill ok">Revoked/);
  assert.doesNotMatch(final, /pill muted">Revoking…/);
});

test('server cannot mutate when the session is detection-only or revoke-disabled', async (t) => {
  const { post } = await live(t, async () => assert.fail('no provider request'), { enabled: false });
  assert.equal((await post()).status, 403);
});

test('audit startup refuses existing files and links without changing bytes or permissions', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-audit-test-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const original = path.join(directory, 'unrelated.jsonl');
  await writeFile(original, 'unrelated audit data\n', { mode: 0o644 });
  const before = await stat(original);
  const hardlink = path.join(directory, 'hardlink.jsonl');
  await link(original, hardlink);
  const candidates = [original, hardlink];
  if (process.platform !== 'win32') {
    const symbolic = path.join(directory, 'symlink.jsonl');
    await symlink(original, symbolic);
    candidates.push(symbolic);
  }
  for (const auditPath of candidates) {
    await assert.rejects(startReportServer({
      entries: [fakeEntry()], meta: fakeMeta(), revokeEntry: () => assert.fail('no provider mutation'),
      outPath: path.join(directory, 'report.html'), auditPath,
    }), (error) => {
      assert.equal(error.code, 'ERR_WORKBENCH_AUDIT_EXISTS');
      assert.match(errorForReport(error), /select a new --audit file/);
      assert.ok(!errorForReport(error).includes(TOKEN));
      return true;
    });
    assert.equal(await readFile(original, 'utf8'), 'unrelated audit data\n');
    assert.equal((await stat(original)).mode, before.mode);
  }
});

test('audit and HTML output aliases are rejected before listening', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-audit-test-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const actual = path.join(directory, 'actual');
  const alias = path.join(directory, 'alias');
  await mkdir(actual);
  await symlink(actual, alias, process.platform === 'win32' ? 'junction' : 'dir');
  let server;
  try {
    await assert.rejects(async () => {
      server = await startReportServer({ entries: [], meta: fakeMeta(),
        outPath: path.join(alias, 'report.html'), auditPath: path.join(actual, 'report.html') });
    }, /different files/);
  } finally { await server?.close(); }
});

test('default audit paths are exclusive per-session files, created privately before listening', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-audit-test-'));
  const servers = [];
  t.after(async () => {
    await Promise.all(servers.map((server) => server.close()));
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const oldAudit = path.join(directory, 'revocations.jsonl');
  await writeFile(oldAudit, 'unrelated prior session\n', { mode: 0o644 });
  const before = await stat(oldAudit);
  for (let index = 0; index < 2; index++) {
    const server = await startReportServer({ entries: [], meta: fakeMeta(), outPath: path.join(directory, 'report.html') });
    servers.push(server);
    assert.match(path.basename(server.auditPath), /^revocations-[a-f0-9-]+\.jsonl$/);
    assert.equal(await readFile(server.auditPath, 'utf8'), '');
    if (process.platform !== 'win32') assert.equal((await stat(server.auditPath)).mode & 0o777, 0o600);
    assert.equal((await fetch(`${server.url}/api/health`)).status, 200);
  }
  assert.notEqual(servers[0].auditPath, servers[1].auditPath);
  assert.equal(await readFile(oldAudit, 'utf8'), 'unrelated prior session\n');
  assert.equal((await stat(oldAudit)).mode, before.mode);
});

test('detection-only servers do not create audit files or audit directories', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-audit-test-'));
  const parent = path.join(directory, 'unused');
  const server = await startReportServer({ entries: [], meta: { ...fakeMeta(), revokeEnabled: false },
    outPath: path.join(directory, 'report.html'), auditPath: path.join(parent, 'audit.jsonl') });
  t.after(async () => { await server.close(); await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  assert.equal(server.auditPath, null);
  await assert.rejects(stat(parent), (error) => error.code === 'ENOENT');
});

test('an audit write failure fails closed before any provider mutation', async (t) => {
  const report = await live(t, () => assert.fail('no provider request without audit'));
  // Inject a portable descriptor write failure; chmod/unlink would not revoke
  // write access to an already-open descriptor and differ across operating systems.
  const probe = await open(path.join(report.directory, 'owned-probe'), 'wx');
  const prototype = Object.getPrototypeOf(probe);
  await probe.close();
  const original = prototype.writeFile;
  prototype.writeFile = function (data, ...args) {
    if (typeof data === 'string' && data.includes('"status":"attempt_started"')) return Promise.reject(new Error('synthetic audit failure'));
    return original.call(this, data, ...args);
  };
  try {
    const response = await report.post();
    assert.equal(response.status, 500);
    assert.match((await response.json()).error, /no provider request was sent/);
    assert.equal(report.entry.revocationReady, false);
    assert.equal((await report.post()).status, 409);
  } finally { prototype.writeFile = original; }
});

test('request cleanup observes rejections even when sending the error response throws', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-rejection-test-'));
  t.after(() => rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const moduleUrl = new URL('../src/server.mjs', import.meta.url).href;
  const code = `
    import assert from 'node:assert/strict';
    import { ServerResponse } from 'node:http';
    import { startReportServer } from ${JSON.stringify(moduleUrl)};
    const unhandled = [];
    process.on('unhandledRejection', (error) => unhandled.push(error.message));
    ServerResponse.prototype.writeHead = function () {
      setImmediate(() => this.destroy());
      throw new Error('synthetic broken response');
    };
    const server = await startReportServer({ entries: [], meta: { validate: false }, outPath: ${JSON.stringify(path.join(directory, 'report.html'))} });
    try { await fetch(server.url + '/api/health'); } catch {}
    await new Promise(setImmediate);
    await server.close();
    assert.deepEqual(unhandled, []);
  `;
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8', env, timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr || result.error?.message);
});

test('private output refuses symlink targets instead of clobbering another file', async (t) => {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-file-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const victim = path.join(directory, 'original.txt'), output = path.join(directory, 'report.html');
  await writeFile(victim, 'do not replace');
  // Windows may require Developer Mode/admin to create symlinks; junctions only
  // work for directories. Exercise regular-file safety there without escalation.
  if (process.platform === 'win32') {
    await writePrivateFile(output, 'private report');
    assert.equal(await readFile(victim, 'utf8'), 'do not replace');
    return;
  }
  await symlink(victim, output);
  await assert.rejects(writePrivateFile(output, 'unsafe'), /non-regular/);
  assert.equal(await readFile(victim, 'utf8'), 'do not replace');
});
