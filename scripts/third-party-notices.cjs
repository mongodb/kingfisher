#!/usr/bin/env node
'use strict';
// Authoritative Cargo attribution inventory: every workspace member, feature and
// platform, including normal/build edges and proc macros, excluding dev-only
// edges and first-party workspace crates. Non-Cargo attribution is independent.
// Cargo and license generation run offline; fetching/reviewing overrides is an
// explicit maintainer operation, never an implicit part of generation/checking.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const generatorVersion = '4.2.0';
const nonCargoSources = [
  'NOTICE',
  'crates/kingfisher-rules/generated/NOTICES.txt',
  'third-party/kingfisher-vectorscan/NOTICE',
  'third-party/kingfisher-vectorscan/LICENSE-VECTORSCAN',
  'third-party/kingfisher-vectorscan/LICENSE-APACHE',
  'third-party/kingfisher-vectorscan/LICENSE-MIT',
];
function cargo(args, cwd = root) {
  return execFileSync('cargo', args, { cwd, encoding: 'utf8', maxBuffer: 128 * 1024 * 1024,
    env: { ...process.env, CARGO_NET_OFFLINE: 'true' } });
}
function sha256(text) { return createHash('sha256').update(text).digest('hex'); }
function scalar(text) {
  if (text.startsWith('"')) return JSON.parse(text);
  if (text.startsWith("'")) return text.slice(1, -1).replaceAll("''", "'");
  return text;
}
// Standard YAML anchors keep identical license/evidence texts in the shipped
// document only once. Expand before inspecting individual crate blocks so even
// aliases whose definitions belong to another crate are checked fail-closed.
function expandTexts(text) {
  const anchors = new Map();
  return text.replace(/^( +text:[ \t]*)([&*][^\n]*)$/gm, (line, prefix, value) => {
    const alias = /^\*(text_[a-f0-9]{64})$/.exec(value);
    if (alias) {
      assert.ok(anchors.has(alias[1]), `Unknown notice text alias: ${alias[1]}`);
      return prefix + anchors.get(alias[1]);
    }
    const definition = /^&(text_[a-f0-9]{64}) ("[^\n]*")$/.exec(value);
    assert.ok(definition, `Malformed notice text reference: ${value}`);
    const [, name, quoted] = definition;
    assert.ok(!anchors.has(name), `Duplicate notice text anchor: ${name}`);
    assert.equal(name, `text_${sha256(JSON.parse(quoted))}`, `Mismatched notice text anchor: ${name}`);
    anchors.set(name, quoted);
    return prefix + quoted;
  });
}
function deduplicateTexts(text) {
  text = expandTexts(text);
  const counts = new Map();
  const pattern = /^( +text:[ \t]*)("[^\n]*")$/gm;
  for (const [, , quoted] of text.matchAll(pattern)) counts.set(quoted, (counts.get(quoted) || 0) + 1);
  const seen = new Set();
  return text.replace(pattern, (line, prefix, quoted) => {
    if (counts.get(quoted) === 1) return line;
    const name = `text_${sha256(JSON.parse(quoted))}`;
    if (seen.has(name)) return `${prefix}*${name}`;
    seen.add(name);
    return `${prefix}&${name} ${quoted}`;
  });
}
function inventory(text) {
  assert.match(text, /^root_name: kingfisher-bin\nthird_party_libraries:\n/);
  const cargoText = expandTexts(text).split(/^non_cargo_notices:\n/m)[0];
  const entries = new Map();
  for (const match of cargoText.matchAll(/^- package_name: ([^\n]+)\n  package_version: ([^\n]+)\n[\s\S]*?(?=^- package_name: |$(?![\s\S]))/gm)) {
    const key = `${scalar(match[1])}@${scalar(match[2])}`;
    assert.ok(!entries.has(key), `Duplicate notice: ${key}`);
    entries.set(key, match[0]);
  }
  assert.equal(entries.size, [...cargoText.matchAll(/^- package_name:/gm)].length, 'Malformed notice inventory');
  return entries;
}
function dependencies(run = cargo) {
  const meta = JSON.parse(run(['metadata', '--locked', '--offline', '--all-features', '--format-version', '1']));
  const members = new Set(meta.workspace_members);
  const firstPartyNames = new Set(meta.packages.filter(pkg => members.has(pkg.id)).map(pkg => pkg.name));
  const packages = new Map();
  for (const pkg of meta.packages) {
    const key = `${pkg.name}@${pkg.version}`;
    assert.ok(!packages.has(key), `Ambiguous package sources for ${key}; review source-qualified attribution`);
    packages.set(key, pkg);
  }
  // --workspace includes tools and future members; --all-features includes opt-in
  // validators/GUI/allocators. --target all is a union, not a cross-compilation.
  const tree = run(['tree', '--locked', '--offline', '--workspace', '--all-features', '--target', 'all',
    '--edges', 'normal,build', '--prefix', 'none', '--format', '{p}']);
  const expected = new Map();
  for (const match of tree.matchAll(/^([\w-]+) v([^\s]+)/gm)) {
    const key = `${match[1]}@${match[2]}`;
    const pkg = packages.get(key);
    assert.ok(pkg, `Cargo metadata omitted ${key}`);
    if (members.has(pkg.id) || firstPartyNames.has(pkg.name)) continue;
    assert.ok(pkg.source?.startsWith('registry+https://github.com/rust-lang/crates.io-index'),
      `Review third-party non-crates.io dependency explicitly: ${key}`);
    expected.set(key, pkg);
  }
  assert.ok(expected.size > 0, 'Cargo returned an empty dependency inventory');
  return expected;
}
function licenses(block) {
  const records = [];
  for (const match of block.matchAll(/^  - license: ([^\n]+)\n    text: ([^\n]*)([\s\S]*?)(?=^  - license: |^  license_evidence:|$(?![\s\S]))/gm)) {
    let text = match[2];
    if (/^\|[2+-]*$/.test(text)) {
      const style = text;
      text = match[3].replace(/^\n/, '').replace(/^ {6}/gm, '').replace(/\n+$/, '');
      if (!style.includes('-')) text += '\n';
    } else text = scalar(text);
    records.push({ license: scalar(match[1]), text });
  }
  return records;
}
// Evaluate SPDX AND/OR/WITH expressions, including legacy Cargo slash-as-OR.
// A missing OR alternative can be omitted only when a complete allowed choice
// remains; mandatory conjuncts and exceptions can never be silently discarded.
function satisfies(expression, available) {
  const words = expression.replaceAll('/', ' OR ').match(/[A-Za-z0-9.+-]+|[()]/g) || [];
  let index = 0;
  function atom() {
    if (words[index] === '(') {
      index++; const value = or(); assert.equal(words[index++], ')', `Invalid license: ${expression}`); return value;
    }
    let name = words[index++];
    assert.ok(name && !['AND', 'OR', 'WITH', ')'].includes(name), `Invalid license: ${expression}`);
    if (words[index] === 'WITH') { index++; name += ` WITH ${words[index++]}`; }
    return available.has(name);
  }
  function and() { let value = atom(); while (words[index] === 'AND') { index++; const next = atom(); value = value && next; } return value; }
  function or() { let value = and(); while (words[index] === 'OR') { index++; const next = and(); value = value || next; } return value; }
  const result = or();
  assert.equal(index, words.length, `Unsupported license expression: ${expression}`);
  return result;
}
function declaredLicense(block) { return scalar(block.match(/^  license: ([^\n]+)/m)?.[1] || ''); }
function complete(block, pkg) {
  if (!block || declaredLicense(block) !== pkg.license) return false;
  const records = licenses(block);
  return records.length > 0 && records.every(l => l.text.trim() && l.text.trim() !== 'NOT FOUND') &&
    satisfies(pkg.license, new Set(records.map(l => l.license)));
}
function entry(pkg) {
  const lines = [`- package_name: ${pkg.package_name}`, `  package_version: ${pkg.package_version}`];
  if (pkg.repository) lines.push(`  repository: ${JSON.stringify(pkg.repository)}`);
  lines.push(`  license: ${JSON.stringify(pkg.license)}`, '  licenses:');
  for (const license of pkg.licenses) {
    lines.push(`  - license: ${JSON.stringify(license.license)}`, `    text: ${JSON.stringify(license.text)}`);
    if (license.source) lines.push(`    source: ${JSON.stringify(license.source)}`, `    sha256: ${JSON.stringify(sha256(license.text))}`);
  }
  if (pkg.evidence?.length) {
    lines.push('  license_evidence:');
    for (const evidence of pkg.evidence) lines.push(`  - source: ${JSON.stringify(evidence.source)}`,
      `    sha256: ${JSON.stringify(sha256(evidence.text))}`, `    text: ${JSON.stringify(evidence.text)}`);
  }
  return lines.join('\n') + '\n';
}
function loadOverrides() { return JSON.parse(fs.readFileSync(path.join(__dirname, 'license-overrides', 'index.json'), 'utf8')).packages; }
function overrideEntry(pkg, override) {
  const key = `${pkg.name}@${pkg.version}`;
  assert.equal(pkg.license, override.declaredLicense, `Review changed upstream license: ${key}`);
  const crateDirectory = path.dirname(pkg.manifest_path);
  const archive = path.resolve(crateDirectory, '../../..', 'cache', path.basename(path.dirname(crateDirectory)), `${pkg.name}-${pkg.version}.crate`);
  assert.equal(sha256(fs.readFileSync(archive)), override.crateChecksum, `Review changed crate archive: ${key}`);
  if (override.vcsRevision) {
    const vcs = JSON.parse(fs.readFileSync(path.join(crateDirectory, '.cargo_vcs_info.json'), 'utf8'));
    assert.equal(vcs.git.sha1, override.vcsRevision, `Review changed upstream source: ${key}`);
  }
  function archived(record) {
    assert.equal(path.basename(record.file), record.file, `Unsafe license archive path: ${key}`);
    const text = fs.readFileSync(path.join(__dirname, 'license-overrides', record.file), 'utf8');
    assert.equal(sha256(text), record.sha256, `Changed archived license/evidence: ${key}/${record.file}`);
    if (record.pathInCrate) assert.equal(fs.readFileSync(path.join(crateDirectory, record.pathInCrate), 'utf8'), text,
      `Changed exact-crate license/evidence: ${key}/${record.pathInCrate}`);
    if (record.transform === 'spdx-mit-permission-body') {
      assert.equal(record.license, 'MIT');
      assert.ok(text.includes('Copyright (c) <year> <copyright holders>'));
      // Keep the canonical source verbatim in the archive. Do not turn its
      // generic template copyright fields into fabricated upstream attribution.
      return text.replace('Copyright (c) <year> <copyright holders>\n\n', '');
    }
    assert.ok(!record.transform, `Unknown license transformation: ${key}`);
    return text;
  }
  return entry({ package_name: pkg.name, package_version: pkg.version, repository: pkg.repository, license: pkg.license,
    licenses: override.licenses.map(record => ({ license: record.license, source: record.source, text: archived(record) })),
    evidence: [{ source: 'License-source review policy', text: override.reason },
      ...(override.evidence || []).map(record => ({ source: record.source, text: archived(record) }))] });
}
function validate(entries, expected, overrides = loadOverrides()) {
  const missing = [...expected.keys()].filter(key => !entries.has(key));
  const stale = [...entries.keys()].filter(key => !expected.has(key));
  assert.deepEqual(missing, [], `Missing third-party notices: ${missing.join(', ')}`);
  assert.deepEqual(stale, [], `Stale/first-party notices must be pruned: ${stale.join(', ')}`);
  for (const [key, pkg] of expected) {
    assert.ok(complete(entries.get(key), pkg), `Incomplete/mismatched license text: ${key}; refresh licenses or add a reviewed pinned override (NOT FOUND is never waived)`);
    if (overrides[key]) assert.equal(entries.get(key), overrideEntry(pkg, overrides[key]), `Stale pinned license/provenance: ${key}`);
  }
}
function placeholders(entries, expected) {
  const all = [...entries.values()].reduce((count, block) => count + licenses(block).filter(l => l.text.trim() === 'NOT FOUND').length, 0);
  const current = [...expected.keys()].filter(key => {
    const texts = entries.has(key) ? licenses(entries.get(key)) : [];
    return texts.length === 0 || texts.every(l => l.text.trim() === 'NOT FOUND');
  }).length;
  return { all, current };
}
function bundle(missing, run = cargo) {
  assert.match(run(['bundle-licenses', '--version']), new RegExp(`\\b${generatorVersion.replaceAll('.', '\\.')}\\b`),
    `Install cargo-bundle-licenses ${generatorVersion}: cargo install --locked cargo-bundle-licenses --version ${generatorVersion}`);
  fs.mkdirSync(path.join(root, 'target'), { recursive: true });
  const directory = fs.mkdtempSync(path.join(root, 'target', '.notices-'));
  try {
    // The tool omits build edges. Expose each exact locked crate directly in a
    // private workspace; never change the real manifest/lock or compile code.
    const manifest = ['[package]', 'name = "kingfisher-license-inventory"', 'version = "0.0.0"',
      'edition = "2024"', '[workspace]', '[lib]', 'path = "empty.rs"', '[dependencies]'];
    missing.forEach(([, pkg], index) => manifest.push(`notice_${index} = { package = ${JSON.stringify(pkg.name)}, version = "=${pkg.version}", default-features = false }`));
    fs.writeFileSync(path.join(directory, 'Cargo.toml'), manifest.join('\n') + '\n');
    fs.writeFileSync(path.join(directory, 'empty.rs'), '');
    fs.copyFileSync(path.join(root, 'Cargo.lock'), path.join(directory, 'Cargo.lock'));
    const generated = JSON.parse(run(['bundle-licenses', '--format', 'json'], directory));
    return new Map(generated.third_party_libraries.map(pkg => [`${pkg.package_name}@${pkg.package_version}`, pkg]));
  } finally {
    assert.equal(path.dirname(directory), path.join(root, 'target'));
    assert.ok(path.basename(directory).startsWith('.notices-'));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}
function generate(entries, expected, { overrides = loadOverrides(), generateMissing = bundle, refresh = false } = {}) {
  // Historical retention must not masquerade as dependency coverage. Preserve
  // incorporated material separately, never via stale first-party crate entries.
  for (const key of entries.keys()) if (!expected.has(key)) entries.delete(key);
  for (const [key, pkg] of expected) if (overrides[key]) entries.set(key, overrideEntry(pkg, overrides[key]));
  const missing = [...expected].filter(([key, pkg]) => !overrides[key] && (refresh || !complete(entries.get(key), pkg)));
  if (!missing.length) return;
  const found = generateMissing(missing);
  for (const [key, pkg] of missing) {
    const notice = found.get(key);
    assert.ok(notice, `License generator omitted ${key}`);
    // Selecting a complete OR alternative is valid; dropping any required AND
    // branch is not. validate() rejects any result that does not satisfy SPDX.
    const available = notice.licenses.filter(l => l.text.trim() && l.text.trim() !== 'NOT FOUND');
    assert.ok(satisfies(pkg.license, new Set(available.map(l => l.license))),
      `Unresolved license: ${key}; archive exact-crate text or a pinned, reviewed override`);
    entries.set(key, entry({ ...notice, license: pkg.license, licenses: available }));
  }
}
function nonCargoSection(base = root) {
  const lines = ['non_cargo_notices:'];
  for (const source of nonCargoSources) {
    const text = fs.readFileSync(path.join(base, source), 'utf8');
    lines.push(`- source: ${JSON.stringify(source)}`, `  sha256: ${JSON.stringify(sha256(text))}`, `  text: ${JSON.stringify(text)}`);
  }
  return lines.join('\n') + '\n';
}
function render(entries, supplementary = nonCargoSection()) {
  return deduplicateTexts('root_name: kingfisher-bin\nthird_party_libraries:\n' +
    '# Identical texts are stored once using standard YAML anchors and aliases.\n' +
    '# Each *text_... refers to the full verbatim text at &text_... in this file.\n' +
    [...entries].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, block]) => block).join('') + supplementary);
}
function main(argv = process.argv.slice(2)) {
  assert.ok(argv.length === 1 && ['--check', '--generate', '--refresh'].includes(argv[0]), 'Use --check, --generate or --refresh');
  const file = path.join(root, 'THIRD_PARTY_NOTICES');
  const original = fs.readFileSync(file, 'utf8');
  const entries = inventory(original);
  const expected = dependencies();
  if (argv[0] !== '--check') generate(entries, expected, { refresh: argv[0] === '--refresh' });
  validate(entries, expected);
  const output = render(entries);
  const sdk = path.join(root, 'javascript', 'THIRD_PARTY_NOTICES');
  if (argv[0] === '--check') {
    assert.equal(original, output, 'Non-Cargo notices/order are stale; run make notices');
    assert.equal(fs.readFileSync(sdk, 'utf8'), output, 'SDK notices must match the shared inventory; run make notices');
  } else {
    // No outputs are written until every license and source has passed checks.
    fs.writeFileSync(file, output);
    fs.writeFileSync(sdk, output);
  }
  console.log(`Verified ${expected.size} exact third-party crate/version notices: all workspace members/features/platforms, normal + build + proc macros; dev-only and first-party crates excluded.`);
  console.log(`Unresolved license texts: 0. Preserved ${nonCargoSources.length} independent non-Cargo notice/license sources.`);
}
if (require.main === module) main();
module.exports = { inventory, dependencies, validate, generate, placeholders, licenses, satisfies, entry, complete,
  render, nonCargoSection, nonCargoSources, sha256, expandTexts, deduplicateTexts };
