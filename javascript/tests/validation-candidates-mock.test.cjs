'use strict';

// Facade-only contract tests: no addon, rule compiler, or network is loaded.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { getEventListeners } = require('node:events');
const fs = require('node:fs');
const { createRequire } = require('node:module');
const { compileFunction } = require('node:vm');

async function fixture(t) {
  const calls = [];
  const loads = [];
  class NativeCancellationToken {
    isCancelled = false;
    cancel() { this.isCancelled = true; }
  }
  class NativeFinding {
    constructor(id) { this.id = id; }
    get secret() { return `synthetic-${this.id}`; }
    get captures() { return {}; }
    toObject(redact) {
      return { ruleId: this.id, visible: true, confidence: 'high',
        secret: redact ? '[REDACTED]' : this.secret, captures: {}, location: {} };
    }
    redacted() { return new NativeFinding(this.id); }
  }
  const raw = ['primary', 'helper', 'unrelated'].map(id => new NativeFinding(id));
  const addon = {
    sdkVersion: () => require('../package.json').version,
    NativeCancellationToken,
    loadRules: async options => {
      loads.push(options);
      return { length: 3, cacheStatus: 'bypassed' };
    },
    NativeScanner: class {
      async scan() { return raw; }
    },
    NativeValidator: class {
      withVariables() { return new addon.NativeValidator(); }
      validate(values, indices, timeout, token) {
        calls.push({ values, indices, timeout, token });
        return Promise.resolve([]);
      }
    },
  };
  const filename = require.resolve('../lib/sdk.cjs');
  const originalRequire = createRequire(filename);
  const module = { exports: {} };
  compileFunction(fs.readFileSync(filename, 'utf8'), ['require', 'module'], { filename })(
    id => id === '../_native.cjs' ? addon : originalRequire(id), module);
  const sdk = module.exports;
  const rules = await sdk.Rules.load();
  const scanner = await sdk.Scanner.create({ rules });
  const validator = new sdk.Validator();
  t.after(async () => { await scanner.close(); await validator.close(); });
  return { sdk, scanner, validator, raw, calls, loads, findings: await scanner.scan('synthetic') };
}

test('mock native: explicit candidates forward ordered indices with the entire raw batch', async t => {
  const { validator, findings, raw, calls } = await fixture(t);
  assert.deepEqual(await validator.validate(Object.freeze(findings), {
    candidates: Object.freeze([findings[2], findings[0]]), timeoutMs: 5000,
  }), []);
  assert.deepEqual(calls[0].values, raw);
  assert.deepEqual(calls[0].indices, [2, 0]);
  assert.ok(calls[0].timeout > 0 && calls[0].timeout <= 5000);
  assert.equal(calls[0].token.isCancelled, false);

  await validator.validate(findings);
  assert.equal(calls[1].indices, undefined); // Existing batch behavior is untouched.
  await validator.validate(findings, { candidates: [] });
  assert.deepEqual(calls[2].indices, []); // Never translate empty selection to default.
  const overlay = validator.withVariables({ USER: 'synthetic' });
  try {
    await overlay.validate(findings, { candidates: [findings[1]] });
    assert.deepEqual(calls[3].indices, [1]);
  } finally { await overlay.close(); }
});

test('mock native: candidates require unique exact original Finding members', async t => {
  const { sdk, scanner, validator, findings, calls } = await fixture(t);
  const [foreign] = await scanner.scan('another input');
  const invalidLists = [null, 1, true, 'primary', {}, new Set(findings)];
  for (const candidates of invalidLists) {
    await assert.rejects(validator.validate(findings, { candidates }), TypeError);
  }
  const invalidMembers = [null, undefined, 0, findings[0].toJSON(),
    Object.create(sdk.Finding.prototype), new Proxy(findings[0], {}),
    findings[0].redacted(), foreign];
  for (const candidate of invalidMembers) {
    await assert.rejects(validator.validate(findings, { candidates: [candidate] }), TypeError);
  }
  await assert.rejects(validator.validate(findings, { candidates: [findings[0], findings[0]] }), /duplicates/);
  await assert.rejects(validator.validate(findings, { candidates: new Array(1) }), TypeError);
  await assert.rejects(validator.validate(new Array(1), { candidates: [] }), TypeError);
  await assert.rejects(validator.validate([], { candidates: [findings[0]] }), /members/);
  await assert.rejects(validator.validate(findings, null), TypeError);
  assert.equal(calls.length, 0); // Reject before the native validation boundary.
});

test('mock native: submitted arrays are snapshots, not mutable selection state', async t => {
  const { validator, findings, raw, calls } = await fixture(t);
  const candidates = [findings[2], findings[0]];
  const pending = validator.validate(findings, { candidates });
  findings.reverse();
  candidates.splice(0, candidates.length);
  await pending;
  assert.deepEqual(calls[0].values, raw);
  assert.deepEqual(calls[0].indices, [2, 0]);
});

test('mock native: explicit and empty selections retain cancellation and error contracts', async t => {
  const { sdk, validator, findings, calls } = await fixture(t);
  for (const candidates of [[], [findings[0]]]) {
    const controller = new AbortController();
    const reason = new Error('cancel selected checks');
    controller.abort(reason);
    await assert.rejects(validator.validate(findings, { candidates, signal: controller.signal }),
      error => error instanceof sdk.AbortError && error.code === 'ERR_KINGFISHER_CANCELLED' && error.cause === reason);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    const token = new sdk.CancellationToken();
    token.cancel();
    await assert.rejects(validator.validate(findings, { candidates, cancellation: token }), sdk.AbortError);
  }
  await assert.rejects(validator.validate(findings, { candidates: [], timeoutMs: 0 }), RangeError);
  assert.equal(calls.length, 0);
});

test('mock native: dependency loading is an explicitly validated opt-in', async t => {
  const { sdk, loads } = await fixture(t);
  assert.equal(loads[0].includeDependencies, false);
  await sdk.Rules.load({ includeDependencies: true, confidence: 'high' });
  assert.equal(loads[1].includeDependencies, true);
  assert.equal(loads[1].confidence, 'high');
  await assert.rejects(sdk.Rules.load({ includeDependencies: 'true' }), TypeError);
  assert.equal(loads.length, 2);
});
