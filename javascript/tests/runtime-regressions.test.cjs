'use strict';

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { getEventListeners } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const {
  Rules, Scanner, ScanInput, Validator, Revoker, filesystem, gitInputs, gitHistory,
  expandArchives, expandContent, AbortError, TimeoutError, KingfisherError, DetectionPolicy,
} = require('../index.cjs');
const { TOKEN, temporary, rulesIn, server, httpRule } = require('./helpers.cjs');

let directory;
let rules;
let scanner;
before(async () => {
  directory = temporary();
  rules = await rulesIn(directory);
  scanner = await Scanner.create({ rules });
});
after(async () => {
  await scanner?.close();
  fs.rmSync(directory, { recursive: true, force: true });
});

function warningRoot() {
  const root = fs.mkdtempSync(path.join(directory, 'warning-'));
  fs.writeFileSync(path.join(root, '.ignore'), '[z-a]\n');
  return root;
}

const factories = {
  filesystem: (root, options) => filesystem([root], options),
  gitInputs,
  gitHistory,
};
for (const [name, factory] of Object.entries(factories)) {
  test(`${name} does not acquire listeners or native resources before first next()`, async () => {
    const controller = new AbortController();
    const iterator = factory(path.join(directory, 'never-opened'), { signal: controller.signal });
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    await iterator.return();
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    assert.equal((await iterator.next()).done, true);
    assert.throws(() => factory(directory, { signal: {} }), TypeError);
    assert.throws(() => factory(directory, { timeoutMs: 0 }), RangeError);
  });
}

test('input iterators clean listeners after success, failed initialization, and JS callback errors', async () => {
  const controller = new AbortController();
  const iterator = filesystem([directory], { signal: controller.signal });
  assert.equal((await iterator.next()).done, false);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 1);
  await iterator.return();
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);

  const failed = new AbortController();
  await assert.rejects(gitInputs(path.join(directory, 'missing-repository'), { signal: failed.signal }).next(),
    error => error.code === 'ERR_KINGFISHER_INPUT');
  assert.equal(getEventListeners(failed.signal, 'abort').length, 0);
  await assert.rejects(filesystem([path.join(directory, 'missing-root')], { signal: failed.signal }).next(),
    error => error.code === 'ERR_KINGFISHER_INPUT');
  assert.equal(getEventListeners(failed.signal, 'abort').length, 0);

  const callback = new AbortController();
  const original = new Error('callback failed', { cause: new Error('callback cause') });
  original.code = 'APPLICATION_WARNING';
  await assert.rejects(filesystem([warningRoot()], {
    signal: callback.signal, onWarning() { throw original; },
  }).next(), error => error === original);
  assert.equal(getEventListeners(callback.signal, 'abort').length, 0);
});

test('warning callbacks preserve native-looking errors and primitive throws while closing resources', async t => {
  const { NativeInputCursor } = require('../_native.cjs');
  const originalClose = NativeInputCursor.prototype.close;
  const close = t.mock.method(NativeInputCursor.prototype, 'close', function () {
    return originalClose.call(this);
  });
  const failures = [
    new Error('KF_TIMEOUT: application callback failed'),
    new Error('KF_CANCELLED: application callback failed'),
    'KF_TIMEOUT: primitive callback failed',
    null, undefined, 0, false, Symbol('callback failure'),
  ];
  for (const failure of failures) {
    const controller = new AbortController();
    const iterator = filesystem([warningRoot()], {
      signal: controller.signal, onWarning() { throw failure; },
    });
    const closedBefore = close.mock.callCount();
    await assert.rejects(iterator.next(), error => error === failure);
    assert.equal(close.mock.callCount(), closedBefore + 1);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    assert.equal((await iterator.next()).done, true);
    await iterator.return();
    assert.equal(close.mock.callCount(), closedBefore + 1);
  }
});

test('cancellation from a warning callback rejects next() and cleans its listener', async () => {
  const controller = new AbortController();
  const reason = new DOMException('cancel during warning', 'TimeoutError');
  const iterator = filesystem([warningRoot(), directory], {
    signal: controller.signal, onWarning() { controller.abort(reason); },
  });
  await assert.rejects(iterator.next(), error => error instanceof TimeoutError && error.cause === reason);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  assert.equal((await iterator.next()).done, true);
});

for (const [name, ErrorClass, code] of [
  ['TimeoutError', TimeoutError, 'ERR_KINGFISHER_TIMEOUT'],
  ['AbortError', AbortError, 'ERR_KINGFISHER_CANCELLED'],
  ['null', AbortError, 'ERR_KINGFISHER_CANCELLED'],
]) {
  test(`pre-aborted ${name} reasons retain SDK identity and original causes across adapters`, async () => {
    const controller = new AbortController();
    const reason = name === 'null' ? null : new DOMException('application reason is retained only as cause', name);
    controller.abort(reason);
    const input = new ScanInput({ path: 'input.env', data: TOKEN });
    const operations = [
      () => scanner.scan(TOKEN, { signal: controller.signal }),
      () => Rules.load({ builtins: false, signal: controller.signal }),
      () => filesystem([directory], { signal: controller.signal }).next(),
      () => gitInputs(directory, { signal: controller.signal }).next(),
      () => expandArchives([input], { signal: controller.signal }).next(),
      () => expandContent([input], { signal: controller.signal }).next(),
    ];
    for (const operation of operations) {
      await assert.rejects(operation(), error => {
        assert.ok(error instanceof ErrorClass);
        assert.equal(error.code, code);
        assert.equal(error.cause, reason);
        assert.ok(!error.message.includes('application reason'));
        return true;
      });
      assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    }
  });
}

test('untagged native conversion and async failures become SDK errors with original causes', async t => {
  await assert.rejects(Scanner.create({ rules, policy: Object.create(DetectionPolicy.prototype) }), error => {
    assert.ok(error instanceof KingfisherError);
    assert.equal(error.code, 'ERR_KINGFISHER_NATIVE');
    assert.equal(error.cause.code, 'InvalidArg');
    assert.match(error.cause.message, /inlineIgnores/);
    return true;
  });
  const { NativeScanner } = require('../_native.cjs');
  const original = new Error('untagged native rejection');
  original.code = 'GenericFailure';
  t.mock.method(NativeScanner.prototype, 'scan', () => Promise.reject(original));
  await assert.rejects(scanner.scan(TOKEN), error => error instanceof KingfisherError &&
    error.code === 'ERR_KINGFISHER_NATIVE' && error.cause === original);
  await assert.rejects(scanner.scan(42), TypeError);
});

test('composition retains native-looking application failures without wrapping', async t => {
  const revoker = await Revoker.create({ rules });
  const original = new Error('KF_TIMEOUT: application scanner factory');
  t.mock.method(Scanner, 'create', async () => { throw original; });
  try { await assert.rejects(revoker.prepare(TOKEN), error => error === original); }
  finally { await revoker.close(); }
});

test('AbortSignal.timeout yields the SDK TimeoutError rather than cancellation', async () => {
  const signal = AbortSignal.timeout(1);
  await delay(10);
  await assert.rejects(scanner.scan(TOKEN, { signal }), error => {
    assert.ok(error instanceof TimeoutError);
    assert.equal(error.cause, signal.reason);
    return true;
  });
});

test('in-flight native cancellation retains signal reason and revocation outcome uncertainty', { timeout: 15000 }, async () => {
  const fixture = temporary();
  let started;
  const mock = await server(() => started()); // Cancellation must interrupt the pending response.
  const validator = new Validator({ allowInternalIps: true });
  let detector;
  let revoker;
  try {
    const fixtureRules = await rulesIn(fixture, httpRule(mock.url));
    detector = await Scanner.create({ rules: fixtureRules });
    revoker = await Revoker.create({ rules: fixtureRules });
    const findings = await detector.scan(TOKEN);
    for (const [name, ErrorClass] of [['TimeoutError', TimeoutError], ['AbortError', AbortError], ['null', AbortError]]) {
      for (const mutation of [false, true]) {
        const submitted = new Promise(resolve => { started = resolve; });
        const controller = new AbortController();
        const reason = name === 'null' ? null : new DOMException('original signal reason', name);
        const call = mutation ?
          revoker.revokeSecret('acme.node-token', TOKEN, { confirm: true, signal: controller.signal }) :
          validator.validate(findings, { signal: controller.signal });
        const rejected = assert.rejects(call, error => {
          assert.ok(error instanceof ErrorClass);
          assert.equal(error.cause, reason);
          assert.equal(error.outcomeUnknown, mutation ? true : undefined);
          assert.ok(!error.message.includes('original signal reason'));
          if (mutation) assert.match(error.message, /outcome (?:is |may be )?unknown|unknown.*outcome/i);
          return true;
        });
        await submitted;
        controller.abort(reason);
        await rejected;
        assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
      }
    }
  } finally {
    await detector?.close(); await revoker?.close(); await validator.close(); await mock.close();
    fs.rmSync(fixture, { recursive: true, force: true });
  }
});

test('concurrent revocation preparations cache one scanner promise and close the owned scanner', async t => {
  const revoker = await Revoker.create({ rules });
  const original = Scanner.create;
  const created = [];
  let release;
  let count = 0;
  const ready = new Promise(resolve => { release = resolve; });
  t.mock.method(Scanner, 'create', async function (options) {
    count++;
    await ready;
    const value = await original.call(this, options);
    created.push(value);
    return value;
  });
  try {
    const calls = [revoker.prepare(TOKEN), revoker.prepare(TOKEN)];
    assert.equal(count, 1);
    release();
    const plans = await Promise.all(calls);
    assert.ok(plans.every(plan => plan.candidates.length === 1));
    assert.equal(created.length, 1);
    await revoker.close();
    await assert.rejects(created[0].scan(TOKEN), error => error.code === 'ERR_KINGFISHER_CLOSED');
  } finally { release(); await revoker.close(); }
});

test('close waits for pending scanner creation and preparation never scans afterward', async t => {
  const revoker = await Revoker.create({ rules });
  const original = Scanner.create;
  let release;
  let created;
  let scanned = 0;
  const ready = new Promise(resolve => { release = resolve; });
  t.mock.method(Scanner, 'create', async function (options) {
    await ready;
    created = await original.call(this, options);
    return created;
  });
  const { NativeScanner } = require('../_native.cjs');
  t.mock.method(NativeScanner.prototype, 'scan', function () {
    scanned++;
    throw new Error('native scan submitted after cancellation');
  });
  try {
    const calls = [revoker.prepare(TOKEN), revoker.prepare(TOKEN)];
    const rejected = Promise.all(calls.map(call => assert.rejects(call, AbortError)));
    const closing = revoker.close();
    let closed = false;
    closing.then(() => { closed = true; });
    await Promise.resolve();
    assert.equal(closed, false);
    release();
    await Promise.all([closing, rejected]);
    assert.equal(scanned, 0);
    // Restore the public scan method before observing the owned scanner state.
    t.mock.restoreAll();
    await assert.rejects(created.scan(TOKEN), error => error.code === 'ERR_KINGFISHER_CLOSED');
  } finally { release(); await revoker.close(); }
});

test('failed cached scanner creation preserves JS errors and permits a retry', async t => {
  const revoker = await Revoker.create({ rules });
  const original = Scanner.create;
  const failure = new Error('application scanner setup failed', { cause: new Error('setup cause') });
  failure.code = 'APPLICATION_SETUP';
  let calls = 0;
  t.mock.method(Scanner, 'create', async function (options) {
    if (++calls === 1) throw failure;
    return await original.call(this, options);
  });
  try {
    await assert.rejects(revoker.prepare(TOKEN), error => error === failure);
    assert.equal((await revoker.prepare(TOKEN)).candidates.length, 1);
    assert.equal(calls, 2);
  } finally { await revoker.close(); }
});
