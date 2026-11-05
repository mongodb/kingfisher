// Run: node examples/archive-content.mjs
// Synthetic gzip content; no external downloads or provider requests.
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { Rules, Scanner, ScanInput, expandArchives, expandContent } from '../index.mjs';

const rules = await Rules.load({
  paths: [fileURLToPath(new URL('./fixtures/acme-token.yml', import.meta.url))],
  builtins: false, cache: false,
});
const scanner = await Scanner.create({ rules });
try {
  const input = new ScanInput({
    path: 'config.env.gz',
    data: gzipSync('ACME_TOKEN=acme_demo_a9B2c7D4e1F8g3H6\n'),
    repository: 'synthetic-demo',
  });
  const members = expandArchives([input], { depth: 1, maxBytes: 1024 * 1024, maxEntries: 10 });
  const text = expandContent(members, { sqlite: true, pyc: true, pdf: false, strict: true });
  let count = 0;
  for await (const result of scanner.scanInputs(text, { timeoutMs: 5000 })) {
    assert.equal(result.findings.length, 1);
    assert.equal(result.input.repository, 'synthetic-demo');
    console.log(JSON.stringify(result.toJSON()));
    count += 1;
  }
  assert.equal(count, 1);
} finally { await scanner.close(); }
