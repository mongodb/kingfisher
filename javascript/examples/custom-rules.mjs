// Run: node examples/custom-rules.mjs
// Offline: mix Kingfisher YAML and Betterleaks TOML, inspect, then detect.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Rules, Scanner } from '../index.mjs';

const paths = ['acme-token.yml', 'acme-token.toml'].map(name =>
  fileURLToPath(new URL(`./fixtures/${name}`, import.meta.url)));
const rules = await Rules.load({ paths, builtins: false, cache: false });
const yamlId = 'acme.example-token';
const tomlId = 'custom.acme-example-toml';

assert.deepEqual(rules.resolve(yamlId), [yamlId]);
assert.deepEqual(rules.resolve(tomlId), [tomlId]);
console.log(JSON.stringify({ phase: 'catalog', rules: rules.metadata(), cacheStatus: rules.cacheStatus }));
console.log(JSON.stringify({ phase: 'definition', id: yamlId, pattern: rules.detail(yamlId).pattern }));

const scanner = await Scanner.create({ rules, base64: false });
try {
  const source = 'YAML=acme_demo_a9B2c7D4e1F8g3H6\nTOML=acme_toml_a9B2c7D4e1F8g3H6\n';
  const findings = await scanner.scan(source, { path: 'mixed.env', timeoutMs: 5000 });
  assert.deepEqual(findings.map(f => f.ruleId).sort(), [yamlId, tomlId].sort());
  console.log(JSON.stringify({ phase: 'scan', findings: findings.map(f => f.toJSON()) }));
} finally { await scanner.close(); }
