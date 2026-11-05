'use strict';

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { inspect } = require('node:util');
const sdk = require('../index.cjs');
const { TOKEN, temporary, rulesIn } = require('./helpers.cjs');

let directory;
let rules;
const resources = new Set();
async function scanner(options = {}) {
  const value = await sdk.Scanner.create({ rules, ...options });
  resources.add(value);
  return value;
}
before(async () => { directory = temporary(); rules = await rulesIn(directory); });
after(async () => {
  await Promise.all([...resources].map(value => value.close()));
  fs.rmSync(directory, { recursive: true, force: true });
});

test('CommonJS, ESM and subpaths share the same SDK classes', async () => {
  const esm = await import('../index.mjs');
  assert.equal(esm.Scanner, sdk.Scanner);
  assert.equal(esm.default, sdk);
  for (const subpath of ['core', 'rules', 'scanner', 'inputs', 'git', 'validation', 'revocation']) {
    const cjs = require(`../${subpath}.cjs`);
    const esm = await import(`../${subpath}.mjs`);
    assert.equal(esm.default, cjs);
    for (const [name, value] of Object.entries(cjs)) {
      assert.equal(value, sdk[name]);
      assert.equal(esm[name], value);
    }
  }
});

test('rule inspection and selection are offline, exact and deterministic', () => {
  assert.equal(rules.length, 1);
  assert.equal(rules.cacheStatus, 'bypassed');
  assert.deepEqual(rules.resolve('acme'), ['acme.node-token']);
  assert.deepEqual(rules.resolve('ACME NODE TOKEN'), ['acme.node-token']);
  const detail = rules.detail('acme.node-token');
  assert.match(detail.pattern, /kf_/);
  detail.pattern = 'changed';
  assert.notEqual(rules.detail('acme.node-token').pattern, 'changed');
  assert.throws(() => rules.resolve('acmee'), RangeError);
  assert.throws(() => rules.detail('unknown'), TypeError);
});

test('custom Betterleaks TOML uses the custom namespace', async () => {
  const file = path.join(directory, 'company.toml');
  fs.writeFileSync(file, `[[rules]]\nid = "acme-toml"\ndescription = "Acme TOML token"\nregex = '''\\b(toml_[a-z0-9]{16})\\b'''\n`);
  const custom = await sdk.Rules.load({ paths: [file], builtins: false, cache: false });
  const value = await sdk.Scanner.create({ rules: custom });
  resources.add(value);
  assert.deepEqual(custom.resolve('acme'), ['custom.acme-toml']);
  assert.equal((await value.scan('toml_abcd1234efgh5678'))[0].ruleId, 'custom.acme-toml');
});

test('text, bytes, typed-array slices and files use the same native detector', async () => {
  const value = await scanner();
  const padded = Buffer.from(`__${TOKEN}__`);
  const slice = new Uint8Array(padded.buffer, padded.byteOffset + 2, TOKEN.length);
  const file = path.join(directory, 'configuration.env');
  fs.writeFileSync(file, TOKEN);
  for (const findings of [await value.scan(TOKEN), await value.scan(Buffer.from(TOKEN)),
    await value.scan(slice), await value.scanFile(file)]) {
    assert.equal(findings.length, 1);
    assert.equal(findings[0].secret, TOKEN);
    assert.match(findings[0].fingerprint, /^[0-9a-f]{16}$/);
  }
  assert.equal((await value.scan('ordinary configuration')).length, 0);
  await assert.rejects(value.scanFile(path.join(directory, 'missing')), error => error.code === 'ERR_KINGFISHER_IO');
});

test('caller buffer mutation cannot change an already submitted scan', async () => {
  const value = await scanner();
  const input = Buffer.from(TOKEN);
  const pending = value.scan(input);
  input.fill(0);
  assert.equal((await pending)[0].secret, TOKEN);
});

test('shared backing stores cannot race native reads', async () => {
  const value = await scanner();
  const shared = new SharedArrayBuffer(TOKEN.length);
  const data = new Uint8Array(shared);
  data.set(Buffer.from(TOKEN));
  await assert.rejects(value.scan(data), TypeError);
  await assert.rejects(value.scan(Buffer.from(shared)), TypeError);
  assert.throws(() => sdk.shannonEntropy(data), TypeError);
  assert.throws(() => new sdk.ScanInput({ path: 'shared.env', data }), TypeError);
  assert.equal((await value.scan(Buffer.from(data)))[0].secret, TOKEN);
});

test('locations are byte offsets, including Unicode prefixes and normalized UTF-16', async () => {
  const value = await scanner();
  const prefix = '😺 configuration: ';
  const finding = (await value.scan(prefix + TOKEN))[0];
  assert.equal(finding.location.startOffset, Buffer.byteLength(prefix));
  assert.equal(finding.location.endOffset, Buffer.byteLength(prefix + TOKEN));
  const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(TOKEN, 'utf16le')]);
  const normalized = (await value.scan(utf16))[0];
  assert.equal(normalized.secret, TOKEN);
  assert.equal(normalized.location.endOffset - normalized.location.startOffset, TOKEN.length);
});

test('default JSON and inspection redact secrets while explicit access retains them', async () => {
  const value = await scanner();
  const finding = (await value.scan(TOKEN))[0];
  assert.equal(finding.toJSON().secret, '[REDACTED]');
  assert.equal(finding.toObject({ redact: false }).secret, TOKEN);
  assert.equal(finding.secret, TOKEN);
  assert.ok(!JSON.stringify(finding).includes(TOKEN));
  assert.ok(!inspect(finding, { depth: 10, showHidden: true }).includes(TOKEN));
  const validator = new sdk.Validator();
  resources.add(validator);
  const [validated] = await validator.validate([finding.redacted()]);
  assert.ok(!JSON.stringify(validated).includes(TOKEN));
});

test('detection policies are opt-in and decode bounded nested Base64', async () => {
  const legacy = await scanner();
  const contextual = await sdk.DetectionScanner.create({ rules });
  resources.add(contextual);
  assert.equal((await legacy.scan(`${TOKEN} # kingfisher:ignore`)).length, 1);
  assert.equal((await contextual.scan(`${TOKEN} # kingfisher:ignore`)).length, 0);
  const single = Buffer.from(`token=${TOKEN}`).toString('base64');
  const nested = Buffer.from(single).toString('base64');
  assert.equal((await legacy.scan(single))[0].isBase64Encoded, true);
  assert.equal((await legacy.scan(nested)).length, 0);
  assert.equal((await contextual.scan(nested))[0].secret, TOKEN);
});

test('deduplication is reusable, path-aware and not committed by an interrupted call', async () => {
  const value = await scanner({ dedup: true });
  const cancellation = new sdk.CancellationToken();
  cancellation.cancel();
  await assert.rejects(value.scan(TOKEN, { cancellation }), sdk.AbortError);
  assert.equal((await value.scan(TOKEN, { path: 'one.env' })).length, 1);
  assert.equal((await value.scan(TOKEN, { path: 'one.env' })).length, 0);
  assert.equal((await value.scan(TOKEN, { path: 'two.env' })).length, 1);
  value.resetDedup();
  assert.equal((await value.scan(TOKEN, { path: 'one.env' })).length, 1);
});

test('timeouts, cancellation, input caps and lifecycle produce failures, not empty scans', async () => {
  const value = await scanner({ maxInputBytes: 16 });
  await assert.rejects(value.scan(TOKEN), error => error.code === 'ERR_KINGFISHER_LIMIT');
  const normal = await scanner();
  await assert.rejects(normal.scan(TOKEN, { timeoutMs: 0.000001 }), sdk.TimeoutError);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(normal.scan(TOKEN, { signal: controller.signal }), sdk.AbortError);
  assert.equal((await normal.scan(TOKEN)).length, 1);
  await normal.close();
  await assert.rejects(normal.scan(TOKEN), error => error.code === 'ERR_KINGFISHER_CLOSED');
});

test('pending work is bounded and native scanning does not monopolize the event loop', async () => {
  const value = await scanner({ maxPendingOperations: 1 });
  const input = Buffer.alloc(32 * 1024 * 1024, 120);
  let ticks = 0;
  const timer = setInterval(() => ticks++, 1);
  try {
    const pending = value.scan(input);
    await assert.rejects(value.scan(TOKEN), error => error.code === 'ERR_KINGFISHER_BUSY');
    assert.throws(() => value.resetDedup(), error => error.code === 'ERR_KINGFISHER_BUSY');
    await pending;
    assert.ok(ticks > 0);
  } finally { clearInterval(timer); }
});

test('validation preserves same-input ownership and does not accept JSON lookalikes', async () => {
  const value = await scanner();
  const validator = new sdk.Validator();
  resources.add(validator);
  const first = await value.scan(TOKEN);
  const second = await value.scan(TOKEN);
  const results = await validator.validate(first);
  assert.equal(results[0].outcome, 'not_attempted');
  await assert.rejects(validator.validate([...first, ...second]), TypeError);
  await assert.rejects(validator.validate(first.map(value => value.toJSON())), TypeError);
});

test('input objects retain private snapshots and default representations omit payloads', async () => {
  const value = await scanner();
  const data = Buffer.from(TOKEN);
  const input = new sdk.ScanInput({ path: 'upload.env', data });
  data.fill(0);
  input.data.fill(0);
  assert.equal((await value.scanInput(input)).findings[0].secret, TOKEN);
  assert.ok(!JSON.stringify(input).includes(TOKEN));
  assert.ok(!inspect(input, { depth: 10, showHidden: true }).includes(TOKEN));
  assert.throws(() => new sdk.ScanInput({ path: 'logical', file: 'different' }), RangeError);
});

test('argument validation rejects malformed configuration before native work', async () => {
  assert.throws(() => new sdk.DetectionPolicy({ inlineIgnores: 'yes' }), TypeError);
  assert.throws(() => new sdk.Validator({ concurrency: 0 }), RangeError);
  assert.throws(() => sdk.filesystem('not-an-array'), TypeError);
  await assert.rejects(sdk.Scanner.create({ minEntropy: NaN }), RangeError);
  await assert.rejects(sdk.Rules.load({ confidence: 'unknown' }), RangeError);
  assert.equal(sdk.shannonEntropy(''), 0);
  assert.equal(sdk.shannonEntropy('aabb'), 1);
});
