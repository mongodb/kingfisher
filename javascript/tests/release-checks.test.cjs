'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { checkABI, floors } = require('../scripts/check-linux-abi.cjs');
const { inventory, validate, placeholders, generate } = require('../../scripts/third-party-notices.cjs');

const imported = version => `  12: 0000000000000000 0 FUNC GLOBAL DEFAULT UND example@${version} (2)`;
const needed = libraries => libraries.map(name => ` 0x0000000000000001 (NEEDED) Shared library: [${name}]`).join('\n');

test('GNU/Linux audit accepts only imported symbols within the documented GCC 11/glibc baseline', () => {
  assert.deepEqual(floors, { GLIBC: '2.35', GLIBCXX: '3.4.29', CXXABI: '1.3.13' });
  const symbols = [imported('GLIBC_2.17'), imported('GLIBC_2.35'), imported('GLIBCXX_3.4.29'), imported('CXXABI_1.3.13'),
    '  15: 0000000011111111 0 FUNC GLOBAL DEFAULT 12 own_export@@GLIBC_99.0'].join('\n');
  const result = checkABI(symbols, needed(['libc.so.6', 'libm.so.6', 'libgcc_s.so.1', 'libstdc++.so.6']));
  assert.equal(result.versions.length, 4);
  assert.ok(!result.versions.includes('GLIBC_99.0'), 'Definitions must not be mistaken for imported requirements');
});

test('GNU/Linux audit rejects newer or private imports and unexpected shared-library dependencies', () => {
  const baseline = imported('GLIBC_2.17');
  for (const version of ['GLIBC_2.36', 'GLIBCXX_3.4.30', 'CXXABI_1.3.14']) {
    assert.throws(() => checkABI(`${baseline}\n${imported(version)}`, needed(['libc.so.6'])), /exceeds supported floor/);
  }
  assert.throws(() => checkABI(`${baseline}\n${imported('GLIBC_PRIVATE')}`, needed(['libc.so.6'])), /Private or unknown/);
  assert.throws(() => checkABI(baseline, needed(['libc.so.6', 'libssl.so.3'])), /Unexpected shared runtime dependency/);
  assert.throws(() => checkABI(baseline, needed(['libSystem.B.dylib'])), /Expected a GNU\/Linux libc dependency/);
  assert.throws(() => checkABI('not a dynamic symbol table', needed(['libc.so.6'])), /No versioned GLIBC imports/);
});

function block(name, version = '1.0.0', text = 'verbatim license fixture', license = 'MIT') {
  return `- package_name: ${name}\n  package_version: ${version}\n  license: ${license}\n  licenses:\n  - license: ${license}\n    text: ${JSON.stringify(text)}\n`;
}
function document(...blocks) { return 'root_name: kingfisher-bin\nthird_party_libraries:\n' + blocks.join(''); }

test('notice inventory rejects missing license fields', () => {
  const expected = new Map([['normal@1.0.0', { license: 'MIT' }]]);
  const complete = block('normal');
  for (const field of ['  license: MIT\n', '    text: "verbatim license fixture"\n']) {
    const entries = inventory(document(complete.replace(field, '')));
    assert.throws(() => validate(entries, expected, {}), /Incomplete\/mismatched license text/);
  }
});

test('notice checks prune historical placeholders without losing current license text', () => {
  // Keep this unit fixture independent of removed dependency versions/archives.
  const expected = new Map([['current@1.0.0', { name: 'current', version: '1.0.0', license: 'MIT' }]]);
  const entries = inventory(document(block('current'), block('legacy', '1.0.0', 'NOT FOUND')));
  const current = entries.get('current@1.0.0');
  assert.throws(() => validate(entries, expected, {}), /Stale\/first-party/);
  assert.deepEqual(placeholders(entries, expected), { all: 1, current: 0 });
  generate(entries, expected, { overrides: {}, generateMissing: () => { throw new Error('Complete current license must not be refreshed'); } });
  validate(entries, expected, {});
  assert.equal(entries.get('current@1.0.0'), current);
  assert.throws(() => validate(entries, expected, { 'legacy@1.0.0': {} }), /Stale license overrides/);
  assert.deepEqual(placeholders(entries, expected), { all: 0, current: 0 });
  entries.set('current@1.0.0', block('current', '1.0.0', 'NOT FOUND'));
  assert.throws(() => validate(entries, expected, {}), /Incomplete\/mismatched license text/);
  assert.deepEqual(placeholders(entries, expected), { all: 1, current: 1 });
});
