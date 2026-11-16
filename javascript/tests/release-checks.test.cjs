'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { checkABI, floors } = require('../scripts/check-linux-abi.cjs');
const { inventory, dependencies, validate, placeholders, generate } = require('../../scripts/third-party-notices.cjs');

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

test('notice graph includes all workspace features/platforms and normal/build/proc-macro edges', () => {
  const registry = 'registry+https://github.com/rust-lang/crates.io-index';
  const packages = ['kingfisher-bin', 'normal', 'build-helper', 'proc-macro', 'windows-only', 'optional-validator', 'dev-only']
    .map(name => ({ id: name, name, version: '1.0.0', source: name === 'kingfisher-bin' ? null : registry }));
  let trees = 0;
  const expected = dependencies(args => {
    assert.ok(args.includes('--locked') && args.includes('--offline') && args.includes('--all-features'));
    if (args[0] === 'metadata') return JSON.stringify({ packages, workspace_members: ['kingfisher-bin'] });
    assert.equal(args[0], 'tree');
    assert.ok(args.includes('--workspace'));
    assert.ok(!args.includes('-p') && !args.includes('--no-proc-macro'));
    assert.equal(args[args.indexOf('--target') + 1], 'all');
    assert.equal(args[args.indexOf('--edges') + 1], 'normal,build');
    trees++;
    return packages.filter(pkg => pkg.name !== 'dev-only').map(pkg => `${pkg.name} v${pkg.version}`).join('\n');
  });
  assert.equal(trees, 1);
  assert.deepEqual([...expected.keys()], ['normal@1.0.0', 'build-helper@1.0.0', 'proc-macro@1.0.0', 'windows-only@1.0.0', 'optional-validator@1.0.0']);
});

test('notice inventory rejects stale versions, duplicates, missing dependencies and incomplete legal fields', () => {
  const expected = new Map([['normal@1.0.0', { license: 'MIT' }], ['build-helper@1.0.0', { license: 'MIT' }]]);
  const entries = inventory(document(block('normal'), block('build-helper'), block('historical-native')));
  assert.throws(() => validate(entries, expected, {}), /Stale\/first-party/);
  entries.delete('historical-native@1.0.0');
  validate(entries, expected, {});
  assert.throws(() => inventory(document(block('normal'), block('normal'))), /Duplicate notice/);
  assert.throws(() => validate(inventory(document(block('normal'))), expected, {}), /Missing third-party notices/);
  entries.set('normal@1.0.0', block('normal').replace('  license: MIT\n', ''));
  assert.throws(() => validate(entries, expected, {}), /Incomplete\/mismatched license text/);
  entries.set('normal@1.0.0', block('normal').replace(/^    text: .*\n/m, ''));
  assert.throws(() => validate(entries, expected, {}), /Incomplete\/mismatched license text/);
});

test('removed schemafy and Inflector retain neither live overrides nor shipped notices', () => {
  const directory = path.resolve(__dirname, '../../scripts/license-overrides');
  const overrides = JSON.parse(fs.readFileSync(path.join(directory, 'index.json'), 'utf8')).packages;
  const entries = inventory(fs.readFileSync(path.resolve(__dirname, '../../THIRD_PARTY_NOTICES'), 'utf8'));
  for (const key of ['schemafy_core@0.6.0', 'schemafy_lib@0.6.0', 'Inflector@0.11.4']) {
    assert.ok(!Object.hasOwn(overrides, key), `Removed dependency must not retain an override: ${key}`);
    assert.ok(!entries.has(key), `Removed dependency must not retain a shipped notice: ${key}`);
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
