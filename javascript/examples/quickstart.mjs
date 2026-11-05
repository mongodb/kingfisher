// Run: node examples/quickstart.mjs
// Offline, deterministic, no writes: all credentials below are synthetic.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Rules, Scanner, ScanInput } from '../index.mjs';

// 1. Load a specific teaching rule. In production, omit builtins:false to
//    combine custom rules with the built-in catalog, or call Rules.load().
const rulesFile = fileURLToPath(new URL('./fixtures/acme-token.yml', import.meta.url));
const rules = await Rules.load({ paths: [rulesFile], builtins: false, cache: false });
const scanner = await Scanner.create({ rules, maxInputBytes: 1024 * 1024 });

try {
  // 2. scan() checks supplied content, not a filename or repository.
  const configuration = 'ACME_TOKEN=acme_demo_a9B2c7D4e1F8g3H6\n';
  const findings = await scanner.scan(configuration, { path: 'config.env', timeoutMs: 5000 });
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'acme.example-token');

  // 3. Emit structured, redacted reports. Keep the original Finding objects
  //    if a later, separately authorized validation operation needs them.
  console.log(JSON.stringify({ phase: 'text', findings: findings.map(f => f.toJSON()) }));

  // 4. Buffer/Uint8Array inputs use the same detector. scanInput() additionally
  //    retains caller-supplied path/provenance in the result.
  const input = new ScanInput({ path: 'memory/config.env', data: Buffer.from(configuration) });
  const result = await scanner.scanInput(input, { timeoutMs: 5000 });
  assert.equal(result.findings.length, 1);
  console.log(JSON.stringify({ phase: 'buffer', ...result.toJSON() }));

  // 5. scanFile() reads exactly one file; it does not recursively enumerate,
  //    decompress, validate, or modify anything.
  const file = fileURLToPath(new URL('./fixtures/project/config.env', import.meta.url));
  const fileFindings = await scanner.scanFile(file, { timeoutMs: 5000 });
  assert.equal(fileFindings.length, 1);
  console.log(JSON.stringify({ phase: 'file', findings: fileFindings.map(f => f.toJSON()) }));
} finally {
  // 6. Always release native resources, including when a call rejects.
  await scanner.close();
}
