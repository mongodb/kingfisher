'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const notices = require('../third-party-notices.cjs');
const registry = 'registry+https://github.com/rust-lang/crates.io-index';
const header = 'root_name: kingfisher-bin\nthird_party_libraries:\n';
function pkg(name, version = '1.0.0', license = 'MIT') {
  return { id: `${registry}#${name}@${version}`, name, version, license, source: registry };
}
function notice(p, texts = [{ license: 'MIT', text: 'Exact upstream license text.\n' }]) {
  return { package_name: p.name, package_version: p.version, license: p.license, licenses: texts };
}
function block(p, texts) { return notices.entry(notice(p, texts)); }
function expected(...packages) { return new Map(packages.map(p => [`${p.name}@${p.version}`, p])); }

test('inventory handles multiline text, duplicate versions and the independent non-Cargo section', () => {
  const p = pkg('sample');
  const text = header + '- package_name: sample\n  package_version: 1.0.0\n  license: MIT\n  licenses:\n  - license: MIT\n    text: |\n      Copyright Example\n\n      Permission text.\n' +
    'non_cargo_notices:\n- source: NOTICE\n  text: "native attributions"\n';
  const entries = notices.inventory(text);
  assert.equal(entries.size, 1);
  assert.equal(notices.licenses(entries.get('sample@1.0.0'))[0].text, 'Copyright Example\n\nPermission text.\n');
  assert.throws(() => notices.inventory(header + block(p) + block(p)), /Duplicate notice/);
});

test('dependency scope follows every workspace member/feature/platform with normal/build and proc-macro edges', () => {
  const member = { ...pkg('kingfisher-tools'), id: 'path+workspace#kingfisher-tools@1.0.0', source: null };
  const main = pkg('runtime');
  const build = pkg('build-helper');
  const macro = pkg('derive-macro');
  const optional = pkg('optional-platform');
  const vectorscan = pkg('kingfisher-vectorscan', '0.1.4');
  const dev = pkg('dev-only');
  const oldFirstParty = pkg('kingfisher-tools', '0.1.0');
  const meta = { workspace_members: [member.id], packages: [member, main, build, macro, optional, vectorscan, dev, oldFirstParty] };
  const calls = [];
  const found = notices.dependencies(args => {
    calls.push(args);
    return args[0] === 'metadata' ? JSON.stringify(meta) :
      [member, main, build, macro, optional, vectorscan, oldFirstParty].map(p => `${p.name} v${p.version}${p.source ? '' : ' (workspace)'}`).join('\n');
  });
  assert.deepEqual([...found.keys()], ['runtime@1.0.0', 'build-helper@1.0.0', 'derive-macro@1.0.0', 'optional-platform@1.0.0', 'kingfisher-vectorscan@0.1.4']);
  for (const args of calls) for (const flag of ['--locked', '--offline', '--all-features']) assert.ok(args.includes(flag));
  const tree = calls[1];
  assert.ok(tree.includes('--workspace'));
  assert.equal(tree[tree.indexOf('--target') + 1], 'all');
  assert.equal(tree[tree.indexOf('--edges') + 1], 'normal,build');
  assert.ok(!tree.includes('--no-proc-macro'));
  assert.ok(!tree.includes('-p'));
});

test('non-workspace path dependencies and ambiguous source identities require explicit review', () => {
  const member = { ...pkg('first-party'), id: 'member', source: null };
  const external = { ...pkg('external-path'), id: 'external', source: null };
  const run = packages => args => args[0] === 'metadata' ?
    JSON.stringify({ workspace_members: [member.id], packages }) : 'external-path v1.0.0 (external)';
  assert.throws(() => notices.dependencies(run([member, external])), /Review third-party non-crates.io/);
  assert.throws(() => notices.dependencies(run([member, external, { ...external, id: 'different-source' }])), /Ambiguous package sources/);
});

test('generation prunes stale and old first-party entries while refreshing existing unresolved text', () => {
  const p = pkg('current');
  const entries = new Map([
    ['current@1.0.0', block(p, [{ license: 'MIT', text: 'NOT FOUND' }])],
    ['stale@0.1.0', block(pkg('stale', '0.1.0'))],
    ['kingfisher-core@0.1.0', block(pkg('kingfisher-core', '0.1.0'))],
  ]);
  let refreshed;
  notices.generate(entries, expected(p), { overrides: {}, generateMissing: missing => {
    refreshed = missing.map(([key]) => key);
    return new Map([['current@1.0.0', notice(p)]]);
  } });
  assert.deepEqual(refreshed, ['current@1.0.0']);
  assert.deepEqual([...entries.keys()], ['current@1.0.0']);
  notices.validate(entries, expected(p), {});
  assert.deepEqual(notices.placeholders(entries, expected(p)), { all: 0, current: 0 });
  const supplementary = 'non_cargo_notices:\n- source: "native NOTICE"\n  text: "incorporated rules/native attribution"\n';
  const rendered = notices.render(entries, supplementary);
  assert.ok(rendered.endsWith(supplementary));
  assert.ok(!rendered.includes('kingfisher-core'));
  assert.equal(notices.inventory(rendered).size, 1);
});

test('strict checks reject stale entries, missing crates, empty text and any unresolved field', () => {
  const p = pkg('current', '1.0.0', 'MIT OR Apache-2.0');
  const good = block(p);
  assert.throws(() => notices.validate(new Map(), expected(p), {}), /Missing third-party/);
  assert.throws(() => notices.validate(new Map([['current@1.0.0', good], ['stale@1.0.0', good]]), expected(p), {}), /Stale\/first-party/);
  for (const text of ['NOT FOUND', ' NOT FOUND\n', '']) {
    const entries = new Map([['current@1.0.0', block(p, [{ license: 'MIT', text: 'available' }, { license: 'Apache-2.0', text }])]]);
    assert.throws(() => notices.validate(entries, expected(p), {}), /Incomplete\/mismatched/);
  }
  const multiline = '  - license: MIT\n    text: |-\n      NOT FOUND\n';
  assert.equal(notices.licenses(multiline)[0].text, 'NOT FOUND');
});

test('refresh allows complete SPDX alternatives, but cannot drop a mandatory conjunction/exception', () => {
  assert.ok(notices.satisfies('(Apache-2.0 OR MIT) AND BSD-3-Clause', new Set(['MIT', 'BSD-3-Clause'])));
  assert.ok(!notices.satisfies('(Apache-2.0 OR MIT) AND BSD-3-Clause', new Set(['MIT'])));
  assert.ok(notices.satisfies('MIT/Apache-2.0', new Set(['Apache-2.0'])));
  assert.ok(!notices.satisfies('Apache-2.0 WITH LLVM-exception', new Set(['Apache-2.0'])));
  assert.ok(notices.satisfies('Apache-2.0 WITH LLVM-exception OR MIT', new Set(['MIT'])));
  const p = pkg('alternative', '1.0.0', 'MIT OR Apache-2.0');
  const entries = new Map([['alternative@1.0.0', block(p, [{ license: 'MIT', text: 'NOT FOUND' }])]]);
  const generateMissing = () => new Map([['alternative@1.0.0', notice(p, [{ license: 'MIT', text: 'exact MIT' }, { license: 'Apache-2.0', text: 'NOT FOUND' }])]]);
  notices.generate(entries, expected(p), { overrides: {}, generateMissing });
  notices.validate(entries, expected(p), {});
  assert.equal(notices.licenses(entries.get('alternative@1.0.0')).length, 1);
  const conjunct = { ...p, license: 'MIT AND BSD-3-Clause' };
  assert.throws(() => notices.generate(new Map(), expected(conjunct), { overrides: {}, generateMissing }), /Unresolved license/);
});

test('forced refresh re-reads even complete entries, while default generation is idempotent', () => {
  const p = pkg('complete');
  const entries = new Map([['complete@1.0.0', block(p)]]);
  notices.generate(entries, expected(p), { overrides: {}, generateMissing: () => { throw new Error('unexpected refresh'); } });
  notices.generate(entries, expected(p), { overrides: {}, refresh: true,
    generateMissing: () => new Map([['complete@1.0.0', notice(p, [{ license: 'MIT', text: 'refreshed exact text' }])]]) });
  assert.equal(notices.licenses(entries.get('complete@1.0.0'))[0].text, 'refreshed exact text');
});

test('non-Cargo notices are copied verbatim, hashed, and independent of Cargo pruning', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kingfisher notices '));
  try {
    for (const source of notices.nonCargoSources) {
      const file = path.join(directory, source);
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, `Copyright fixture: ${source}\nNative/rules attribution.\n`);
    }
    const supplementary = notices.nonCargoSection(directory);
    assert.equal([...supplementary.matchAll(/^- source:/gm)].length, notices.nonCargoSources.length);
    for (const source of notices.nonCargoSources) {
      const text = fs.readFileSync(path.join(directory, source), 'utf8');
      assert.ok(supplementary.includes(JSON.stringify(text)));
      assert.ok(supplementary.includes(JSON.stringify(notices.sha256(text))));
    }
    const file = path.join(directory, notices.nonCargoSources[0]);
    fs.appendFileSync(file, 'Additional required attribution\n');
    assert.notEqual(notices.nonCargoSection(directory), supplementary);
  } finally {
    assert.equal(path.dirname(directory), os.tmpdir());
    assert.ok(path.basename(directory).startsWith('kingfisher notices '));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test('every pinned license/evidence archive matches its recorded hash and exact-version provenance', () => {
  const directory = path.resolve(__dirname, '..', 'license-overrides');
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'index.json'), 'utf8'));
  assert.equal(manifest.schemaVersion, 1);
  assert.ok(Object.keys(manifest.packages).length > 0);
  for (const [key, override] of Object.entries(manifest.packages)) {
    assert.match(key, /@\d/);
    assert.match(override.crateChecksum, /^[a-f0-9]{64}$/);
    if (override.vcsRevision) assert.match(override.vcsRevision, /^[a-f0-9]{40}$/);
    assert.ok(notices.satisfies(override.declaredLicense, new Set(override.licenses.map(l => l.license))), key);
    for (const record of [...override.licenses, ...(override.evidence || [])]) {
      assert.equal(path.basename(record.file), record.file);
      const text = fs.readFileSync(path.join(directory, record.file), 'utf8');
      assert.equal(notices.sha256(text), record.sha256, `${key}/${record.file}`);
      assert.match(record.source, /^https:\/\/(raw\.githubusercontent\.com\/[^/]+\/[^/]+\/[a-f0-9]{40}\/|docs\.rs\/crate\/)/);
      assert.notEqual(text.trim(), 'NOT FOUND');
    }
    if (override.licenses.some(l => l.source.includes('spdx/license-list-data'))) {
      assert.ok(override.evidence.some(e => e.pathInCrate === 'Cargo.toml'), key);
      assert.match(override.reason, /No copyright owner or year is inferred/);
    }
  }
});
