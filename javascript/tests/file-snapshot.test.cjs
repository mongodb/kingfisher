'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Scanner, ScanInput, expandArchives, expandContent } = require('../index.cjs');
const { TOKEN, temporary, rulesIn } = require('./helpers.cjs');

test('file snapshots enforce raw-byte caps, accept exact limits, and reject directories', async () => {
  const directory = temporary();
  const scanners = [];
  try {
    const rules = await rulesIn(directory);
    const file = path.join(directory, 'input.env');
    fs.writeFileSync(file, TOKEN);
    const exact = await Scanner.create({ rules, maxInputBytes: Buffer.byteLength(TOKEN) });
    scanners.push(exact);
    assert.equal((await exact.scanFile(file))[0].secret, TOKEN);
    await assert.rejects(exact.scanFile(directory), error => error.code === 'ERR_KINGFISHER_IO');
    await assert.rejects(exact.scanFile(file, { path: 'logical.env' }), TypeError);
    await assert.rejects(exact.scanFile(file, { attributes: { path: 'logical.env' } }), TypeError);
    assert.equal((await exact.scanFile(file, { attributes: { path: file } }))[0].secret, TOKEN);
    for (const transform of [expandArchives, expandContent]) {
      await assert.rejects(transform([ScanInput.fromFile(directory)]).next(), error => error.code === 'ERR_KINGFISHER_IO');
    }

    const empty = await Scanner.create({ rules, maxInputBytes: 0 });
    scanners.push(empty);
    await assert.rejects(empty.scanFile(file), error => error.code === 'ERR_KINGFISHER_LIMIT');
    fs.writeFileSync(file, '');
    assert.deepEqual(await empty.scanFile(file), []);

    // The raw input cap still applies even when decoding would shrink the bytes.
    fs.writeFileSync(file, Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(TOKEN, 'utf16le')]));
    await assert.rejects(exact.scanFile(file), error => error.code === 'ERR_KINGFISHER_LIMIT');
    const unlimited = await Scanner.create({ rules, maxInputBytes: null });
    scanners.push(unlimited);
    assert.equal((await unlimited.scanFile(file))[0].secret, TOKEN);
  } finally {
    await Promise.all(scanners.map(scanner => scanner.close()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('concurrently truncated files cannot crash the native scanner', { timeout: 40000 }, async () => {
  const directory = temporary();
  try {
    await rulesIn(directory);
    const file = path.join(directory, 'changing.env');
    fs.writeFileSync(file, Buffer.alloc(8 * 1024 * 1024, 120));
    // Keep this in a subprocess: an unsafe mmap regression can SIGBUS/abort the
    // entire Node process, not merely reject its scan Promise.
    const result = spawnSync(process.execPath, ['--eval', `
      const assert = require('node:assert/strict');
      const { Worker } = require('node:worker_threads');
      const { once } = require('node:events');
      const { Rules, Scanner } = require(process.argv[1]);
      (async () => {
        const rules = await Rules.load({ paths: [process.argv[3]], builtins: false, cache: false });
        const scanner = await Scanner.create({ rules, maxInputBytes: 8 * 1024 * 1024 });
        const stop = new Int32Array(new SharedArrayBuffer(4));
        const worker = new Worker(\`
          const fs = require('node:fs');
          const { parentPort, workerData } = require('node:worker_threads');
          const stop = new Int32Array(workerData.stop);
          const file = fs.openSync(workerData.path, 'r+');
          const data = Buffer.alloc(4096, 120);
          try {
            parentPort.postMessage('ready');
            while (!Atomics.load(stop, 0)) {
              fs.ftruncateSync(file, 0);
              fs.writeSync(file, data, 0, data.length, 0);
              fs.ftruncateSync(file, 8 * 1024 * 1024);
            }
          } finally { fs.closeSync(file); }
        \`, { eval: true, workerData: { path: process.argv[2], stop: stop.buffer } });
        const exited = once(worker, 'exit');
        try {
          await once(worker, 'message');
          for (let i = 0; i < 64; i++) {
            assert.ok(Array.isArray(await scanner.scanFile(process.argv[2])));
          }
        } finally {
          Atomics.store(stop, 0, 1);
          await exited;
          await scanner.close();
        }
      })().catch(error => { console.error(error); process.exitCode = 1; });
    `, path.resolve(__dirname, '../index.cjs'), file, path.join(directory, 'rules.yml')], {
      encoding: 'utf8', timeout: 30000,
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null, result.stderr);
    assert.equal(result.status, 0, result.stderr);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
