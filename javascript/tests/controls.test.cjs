'use strict';

const assert = require('node:assert/strict');
const { test, before, after } = require('node:test');
const fs = require('node:fs');
const { getEventListeners } = require('node:events');
const { setTimeout: delay } = require('node:timers/promises');
const { Scanner, ScanInput, expandArchives, expandContent, AbortError, TimeoutError } = require('../index.cjs');
const { TOKEN, temporary, rulesIn, zip } = require('./helpers.cjs');

let directory;
let scanner;
before(async () => {
  directory = temporary();
  scanner = await Scanner.create({ rules: await rulesIn(directory) });
});
after(async () => { await scanner?.close(); fs.rmSync(directory, { recursive: true, force: true }); });

const stages = {
  scanInputs: (inputs, options) => scanner.scanInputs(inputs, options),
  expandArchives,
  expandContent,
};

for (const [name, stage] of Object.entries(stages)) {
  test(`${name} uses one deadline including consumer time and does not pull after expiry`, async () => {
    let pulled = 0;
    let closed = false;
    function* inputs() {
      try {
        pulled++;
        yield new ScanInput({ path: 'first.env', data: TOKEN });
        pulled++;
        yield new ScanInput({ path: 'second.env', data: TOKEN });
      } finally { closed = true; }
    }
    const iterator = stage(inputs(), { timeoutMs: 1000 });
    assert.equal((await iterator.next()).done, false);
    await delay(1050);
    await assert.rejects(iterator.next(), TimeoutError);
    assert.equal(pulled, 1);
    assert.equal(closed, true);
  });

  test(`${name} checks controls when an asynchronous producer finishes without yielding`, async () => {
    async function* expired() { await delay(50); }
    await assert.rejects(stage(expired(), { timeoutMs: 20 }).next(), TimeoutError);

    const controller = new AbortController();
    async function* cancelled() { controller.abort(); }
    await assert.rejects(stage(cancelled(), { signal: controller.signal }).next(), AbortError);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  });

  test(`${name} keeps cancellation until return and cleans up listeners`, async () => {
    const controller = new AbortController();
    const input = new ScanInput({ path: 'input.env', data: TOKEN });
    const iterator = stage([input, input], { signal: controller.signal });
    await iterator.next();
    assert.equal(getEventListeners(controller.signal, 'abort').length, 1);
    controller.abort();
    await assert.rejects(iterator.next(), AbortError);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);

    const stoppedController = new AbortController();
    const stopped = stage([input, input], { signal: stoppedController.signal });
    await stopped.next();
    await stopped.return();
    assert.equal(getEventListeners(stoppedController.signal, 'abort').length, 0);
    assert.equal((await stopped.next()).done, true);
  });

  test(`${name} checks controls even for an empty source and preserves producer errors`, async () => {
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(stage([], { signal: controller.signal }).next(), AbortError);
    const failure = new Error('producer failed');
    async function* inputs() { throw failure; }
    await assert.rejects(stage(inputs()).next(), error => error === failure);
  });
}

test('archive cancellation is checked between buffered members of one root', async () => {
  const input = new ScanInput({ path: 'config.zip', data: zip([['one.env', TOKEN], ['two.env', TOKEN]]) });
  const controller = new AbortController();
  const iterator = expandArchives([input], { signal: controller.signal });
  assert.equal((await iterator.next()).done, false);
  controller.abort();
  await assert.rejects(iterator.next(), AbortError);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});
