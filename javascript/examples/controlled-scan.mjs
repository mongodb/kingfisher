// Run: node examples/controlled-scan.mjs
// Offline: distinguish cancellation/input-limit errors from a clean scan.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Rules, Scanner, CancellationToken, AbortError } from '../index.mjs';

const rules = await Rules.load({
  paths: [fileURLToPath(new URL('./fixtures/acme-token.yml', import.meta.url))],
  builtins: false, cache: false,
});
const scanner = await Scanner.create({ rules, maxInputBytes: 64, maxPendingOperations: 2 });
try {
  const cancellation = new CancellationToken();
  cancellation.cancel(); // A cancelled token cannot be reset; create a new one for new work.
  try {
    await scanner.scan('ordinary configuration', { cancellation, timeoutMs: 5000 });
    assert.fail('Expected an AbortError');
  } catch (error) {
    if (!(error instanceof AbortError)) throw error;
    console.log(JSON.stringify({ phase: 'cancelled', code: error.code }));
  }

  try {
    await scanner.scan(Buffer.alloc(65), { timeoutMs: 5000 });
    assert.fail('Expected the configured per-input limit');
  } catch (error) {
    if (error.code !== 'ERR_KINGFISHER_LIMIT') throw error;
    console.log(JSON.stringify({ phase: 'too-large', code: error.code }));
  }

  // A previous failed operation has not poisoned the scanner. Keep concurrent
  // calls at or below maxPendingOperations instead of starting unbounded work.
  const results = await Promise.all(['ordinary configuration', 'also ordinary'].map(data =>
    scanner.scan(data, { timeoutMs: 5000 })));
  assert.ok(results.every(findings => findings.length === 0));
  console.log(JSON.stringify({ phase: 'completed', inputs: results.length, findings: 0 }));
} finally { await scanner.close(); }
