'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { execFileSync } = require('node:child_process');
const { inspect } = require('node:util');
const { Scanner, ScanInput, filesystem, gitInputs, gitHistory, expandArchives, expandContent, TimeoutError } = require('../index.cjs');
const { TOKEN, temporary, rulesIn, zip } = require('./helpers.cjs');

async function collect(values) { const results = []; for await (const value of values) results.push(value); return results; }

test('filesystem enumeration is lazy, respects local ignores, and skips symlinks and .git', async () => {
  const directory = temporary();
  try {
    fs.writeFileSync(path.join(directory, '.ignore'), 'ignored.env\n');
    fs.writeFileSync(path.join(directory, 'visible.env'), TOKEN);
    fs.writeFileSync(path.join(directory, 'ignored.env'), TOKEN);
    fs.writeFileSync(path.join(directory, '.hidden.env'), TOKEN);
    fs.mkdirSync(path.join(directory, '.git'));
    fs.writeFileSync(path.join(directory, '.git', 'config'), TOKEN);
    const external = path.join(directory, 'target');
    fs.mkdirSync(external);
    fs.writeFileSync(path.join(external, 'nested.env'), TOKEN);
    fs.symlinkSync(external, path.join(directory, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
    const values = await collect(filesystem([directory]));
    assert.deepEqual(values.map(value => path.relative(directory, value.path)).sort(), ['target/nested.env', 'visible.env'].map(value => path.normalize(value)).sort());
    assert.ok(values.every(value => value.data === undefined));
    const hidden = await collect(filesystem([directory], { hidden: true, gitignore: false }));
    assert.ok(hidden.some(value => value.path.endsWith('.hidden.env')));
    assert.ok(!hidden.some(value => value.path.includes(`${path.sep}.git${path.sep}`)));
    const limited = await collect(filesystem([directory], { maxFileSize: 1 }));
    assert.equal(limited.length, 0);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('filesystem paths preserve Unicode and reject names that cannot roundtrip as strings', async t => {
  const directory = temporary();
  try {
    const names = ['配置-🦆.env', 'replacement-\ufffd.env'];
    for (const name of names) fs.writeFileSync(path.join(directory, name), name);
    const values = await collect(filesystem([directory]));
    assert.deepEqual(values.map(value => path.basename(value.path)).sort(), [...names].sort());
    for (const value of values) {
      assert.equal(value.file, value.path);
      assert.equal(fs.readFileSync(value.file, 'utf8'), path.basename(value.path));
    }
    if (process.platform !== 'win32') {
      // A lossy conversion would alias the distinct, valid U+FFFD name above.
      const invalid = Buffer.concat([Buffer.from(path.join(directory, 'replacement-')), Buffer.from([0xff]), Buffer.from('.env')]);
      try { fs.writeFileSync(invalid, 'invalid-byte-name'); }
      catch (error) {
        // Some POSIX filesystems (including APFS) reject non-UTF-8 names themselves.
        if (error.code !== 'EILSEQ' && !(process.platform === 'darwin' && error.code === 'EPERM')) throw error;
        t.diagnostic('filesystem rejects invalid UTF-8 filenames; Unicode roundtrips verified');
        return;
      }
      await assert.rejects(collect(filesystem([directory])), error => {
        assert.equal(error.code, 'ERR_KINGFISHER_INPUT');
        assert.equal(error.message, 'filesystem paths must contain valid Unicode; rename the file or scan its bytes directly');
        return true;
      });
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('iterator controls include consumer time and return() releases native resources', async () => {
  const directory = temporary();
  try {
    fs.writeFileSync(path.join(directory, 'one'), TOKEN);
    fs.writeFileSync(path.join(directory, 'two'), TOKEN);
    const iterator = filesystem([directory], { timeoutMs: 200 });
    await iterator.next();
    await new Promise(resolve => setTimeout(resolve, 250));
    await assert.rejects(iterator.next(), TimeoutError);
    const stopped = filesystem([directory]);
    await stopped.next();
    await stopped.return();
    assert.equal((await stopped.next()).done, true);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('native Git scopes retain original blob and commit provenance without a runtime Git subprocess', async () => {
  const directory = temporary();
  const git = (...args) => execFileSync('git', args, { cwd: directory, stdio: 'pipe' }).toString().trim();
  try {
    git('init', '--quiet');
    git('config', 'user.name', 'Kingfisher SDK Test');
    git('config', 'user.email', 'sdk@example.invalid');
    // Synthetic commits must not inherit a user's signing-key requirements.
    git('config', 'commit.gpgsign', 'false');
    fs.writeFileSync(path.join(directory, 'token.env'), TOKEN);
    git('add', 'token.env');
    git('commit', '--quiet', '-m', 'first');
    const first = git('rev-parse', 'HEAD');
    fs.writeFileSync(path.join(directory, 'token.env'), `changed=${TOKEN}`);
    git('add', 'token.env');
    git('commit', '--quiet', '-m', 'second');
    const latest = git('rev-parse', 'HEAD');
    const history = await collect(gitHistory(directory));
    assert.equal(history.length, 2);
    assert.ok(history.every(value => value.rawPath && value.blobId && value.repository === directory));
    assert.ok(history.some(value => value.origins.some(origin => origin.id === first)));
    assert.ok(history.every(value => typeof value.origins[0].author.timestamp === 'string'));
    assert.ok(!inspect(history, { depth: 10 }).includes(TOKEN));
    const snapshot = await collect(gitInputs(directory, { mode: 'snapshot', refs: ['HEAD'] }));
    assert.equal(snapshot.length, 1);
    assert.equal(snapshot[0].commit, latest);
    assert.equal(Buffer.from(snapshot[0].data).toString(), `changed=${TOKEN}`);
    const diff = await collect(gitInputs(directory, { mode: 'diff', refs: ['HEAD'], sinceCommit: 'HEAD~1' }));
    assert.equal(diff.length, 1);
    fs.writeFileSync(path.join(directory, 'staged.env'), TOKEN);
    git('add', 'staged.env');
    const staged = await collect(gitInputs(directory, { mode: 'staged' }));
    assert.equal(staged.length, 1);
    assert.equal(staged[0].staged, true);
    assert.equal(staged[0].path, 'staged.env');
    const warnings = [];
    assert.equal((await collect(gitInputs(directory, { mode: 'snapshot', maxBlobSize: 1, onWarning: value => warnings.push(value) }))).length, 0);
    assert.equal(warnings[0].reason, 'oversized');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('missing filesystem roots fail rather than produce empty successful scans', async () => {
  const directory = temporary();
  try {
    const missing = path.join(directory, 'missing');
    const file = path.join(directory, 'visible.env');
    fs.writeFileSync(file, TOKEN);
    for (const roots of [[missing], [missing, file], [file, missing]]) {
      const warnings = [];
      const iterator = filesystem(roots, { onWarning: warning => warnings.push(warning) });
      await assert.rejects(collect(iterator), error => error.code === 'ERR_KINGFISHER_INPUT');
      assert.deepEqual(warnings, []);
      assert.equal((await iterator.next()).done, true);
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('recoverable filesystem failures warn with paths and continue other roots', async () => {
  const directory = temporary();
  try {
    const tree = path.join(directory, 'tree');
    fs.mkdirSync(tree);
    for (const name of ['a', 'b']) {
      fs.mkdirSync(path.join(tree, name));
      fs.writeFileSync(path.join(tree, name, 'token.env'), TOKEN);
    }
    const file = path.join(directory, 'visible.env');
    fs.writeFileSync(file, TOKEN);
    const warnings = [];
    const iterator = filesystem([tree, file], { onWarning: warning => warnings.push(warning) });
    const first = (await iterator.next()).value;
    assert.ok(first);
    // The sibling is listed by the walker but has not been entered yet.
    const sibling = path.join(tree, path.basename(path.dirname(first.path)) === 'a' ? 'b' : 'a');
    fs.rmSync(sibling, { recursive: true });
    const values = await collect(iterator);
    assert.deepEqual(values.map(value => value.path), [file]);
    assert.ok(warnings.some(warning => warning.path === sibling && warning.reason === 'walk_error'));
    assert.ok(warnings.every(Object.isFrozen));

    fs.writeFileSync(path.join(directory, '.ignore'), '[z-a]\n');
    const partial = [];
    const continued = await collect(filesystem([directory], { onWarning: warning => partial.push(warning) }));
    assert.ok(continued.some(value => value.path === file));
    assert.ok(partial.some(warning => warning.reason === 'ignore_error' && warning.path === directory));

    const failure = new Error('warning callback failed', { cause: new Error('original cause') });
    failure.code = 'CUSTOM_CALLBACK';
    await assert.rejects(collect(filesystem([directory], { onWarning() { throw failure; } })), error => error === failure);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('parent ignore parse failures warn without rejecting readable selected roots', async () => {
  const directory = temporary();
  try {
    const parent = path.join(directory, 'parent');
    const child = path.join(parent, 'child');
    fs.mkdirSync(child, { recursive: true });
    const ignore = path.join(parent, '.ignore');
    fs.writeFileSync(ignore, '[z-a]\n');
    const nested = path.join(child, 'token.env');
    const independent = path.join(directory, 'independent.env');
    fs.writeFileSync(nested, TOKEN);
    fs.writeFileSync(independent, TOKEN);
    for (const roots of [[child, independent], [independent, child]]) {
      const warnings = [];
      const values = await collect(filesystem(roots, { onWarning: warning => warnings.push(warning) }));
      assert.deepEqual(values.map(value => value.path).sort(), [nested, independent].sort());
      // Native realpaths canonicalize both /var aliases and Windows namespaced paths.
      assert.ok(warnings.some(warning => fs.realpathSync.native(warning.path) === fs.realpathSync.native(ignore)), JSON.stringify(warnings));
      assert.ok(warnings.every(Object.isFrozen));
    }
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('ordinary sources and disabled archive expansion pass through without archive budgets or copies', async () => {
  const directory = temporary();
  try {
    const file = path.join(directory, 'ordinary.env');
    fs.writeFileSync(file, 'plain'.repeat(8192));
    const sources = [new ScanInput({ path: 'ordinary.env', data: fs.readFileSync(file) }), ScanInput.fromFile(file)];
    const ordinary = await collect(expandArchives(sources, { maxBytes: 1 }));
    for (const [index, source] of sources.entries()) assert.equal(ordinary[index], source);

    const missingArchive = ScanInput.fromFile(path.join(directory, 'not-opened.zip'));
    const malformed = new ScanInput({ path: 'malformed.zip', data: 'not a ZIP' });
    for (const source of [...sources, missingArchive, malformed]) {
      assert.equal((await collect(expandArchives([source], { depth: 0, maxBytes: 1 })))[0], source);
    }
    await assert.rejects(collect(expandArchives([new ScanInput({ path: 'archive.zip', data: zip([['file.env', TOKEN]]) })], { maxBytes: 1 })),
      error => error.code === 'ERR_KINGFISHER_LIMIT');

    // Recursing over an ordinary member still works after all extracted bytes
    // have consumed the cumulative budget, because it is not another archive.
    const data = 'x'.repeat(4096);
    const [leaf] = await collect(expandArchives([new ScanInput({ path: 'archive.zip', data: zip([['file.env', data]]) })], { depth: 2, maxBytes: 4096 }));
    assert.equal(Buffer.from(leaf.data).toString(), data);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('nested ZIP expansion preserves metadata and scans each member separately', async () => {
  const directory = temporary();
  let scanner;
  try {
    const rules = await rulesIn(directory);
    scanner = await Scanner.create({ rules });
    const nested = zip([['token.env', TOKEN]]);
    const archive = zip([['nested.zip', nested]]);
    const input = new ScanInput({ path: 'artifact.zip', data: archive, repository: 'original-repository',
      commit: 'original-commit', blobId: 'original-blob' });
    const expanded = await collect(expandArchives([input], { depth: 2 }));
    assert.equal(expanded.length, 1);
    assert.equal(expanded[0].path, 'artifact.zip!nested.zip!token.env');
    assert.equal(expanded[0].blobId, 'original-blob');
    assert.equal(expanded[0].commit, 'original-commit');
    const results = await collect(scanner.scanInputs(expanded));
    assert.equal(results[0].findings[0].secret, TOKEN);
    assert.ok(!JSON.stringify(results).includes(TOKEN));
  } finally { await scanner?.close(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test('unsafe ZIP members reject the complete root rather than omit coverage', async () => {
  const output = [];
  const input = new ScanInput({ path: 'unsafe.zip', data: zip([['safe.env', TOKEN], ['../escape.env', TOKEN]]) });
  await assert.rejects(async () => {
    for await (const value of expandArchives([input])) output.push(value);
  }, error => error.code === 'ERR_KINGFISHER_EXTRACTION');
  assert.equal(output.length, 0);
});

test('archive errors and cumulative budgets never yield a partial root', async () => {
  const archive = zip([['one.env', TOKEN], ['large.env', 'x'.repeat(4096)]]);
  const output = [];
  await assert.rejects(async () => {
    for await (const item of expandArchives([new ScanInput({ path: 'artifact.zip', data: archive })], { maxBytes: 512 })) output.push(item);
  });
  assert.equal(output.length, 0);
  await assert.rejects(collect(expandArchives([new ScanInput({ path: 'malformed.zip', data: 'not a ZIP' })])));
  assert.throws(() => expandArchives([], { maxBytes: 0 }), RangeError);
});

test('stream formats stage only in the selected protected parent and remove staging afterward', async () => {
  const directory = temporary();
  try {
    const parent = path.join(directory, 'parent! with spaces');
    fs.mkdirSync(parent);
    const input = new ScanInput({ path: 'https://example.invalid/export.env.gz', data: zlib.gzipSync(TOKEN) });
    const [expanded] = await collect(expandArchives([input], { tempDir: parent }));
    assert.equal(Buffer.from(expanded.data).toString(), TOKEN);
    assert.match(expanded.path, /^https:\/\/example\.invalid\/export\.env\.gz!/);
    assert.deepEqual(fs.readdirSync(parent), []);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('content extraction keeps safe malformed-input diagnostics and strict failures', async () => {
  const input = new ScanInput({ path: 'malformed.pdf', data: `%PDF-1.7\n${TOKEN}` });
  const [fallback] = await collect(expandContent([input], { pdf: true }));
  assert.equal(fallback.extractionError, 'malformed_pdf');
  assert.equal(Buffer.from(fallback.data).toString(), `%PDF-1.7\n${TOKEN}`);
  assert.ok(!JSON.stringify(fallback).includes(TOKEN));
  await assert.rejects(collect(expandContent([input], { pdf: true, strict: true })));
  const normal = new ScanInput({ path: 'ordinary.env', data: TOKEN });
  assert.equal((await collect(expandContent([normal])))[0], normal);
});

test('SQLite extraction uses a closed staged snapshot and preserves the original database', async () => {
  const { DatabaseSync } = require('node:sqlite');
  const directory = temporary();
  let scanner;
  try {
    const file = path.join(directory, 'config.db');
    const database = new DatabaseSync(file);
    database.exec('CREATE TABLE config (value TEXT)');
    database.prepare('INSERT INTO config VALUES (?)').run(TOKEN);
    database.close();
    const before = fs.readFileSync(file);
    const rules = await rulesIn(directory);
    scanner = await Scanner.create({ rules });
    const inputs = await collect(expandContent([ScanInput.fromFile(file)], { tempDir: directory }));
    assert.ok(inputs[0].path.includes('!'));
    assert.equal((await scanner.scanInput(inputs[0])).findings[0].secret, TOKEN);
    assert.deepEqual(fs.readFileSync(file), before);
    assert.equal(fs.readdirSync(directory).some(value => value.startsWith('kingfisher-node-extract-')), false);
  } finally { await scanner?.close(); fs.rmSync(directory, { recursive: true, force: true }); }
});
