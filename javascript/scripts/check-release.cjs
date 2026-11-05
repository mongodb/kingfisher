'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const targets = require('./targets.cjs');
const notices = ['LICENSE', 'LICENSE-RULES', 'NOTICE', 'NOTICE-VECTORSCAN',
  'LICENSE-VECTORSCAN', 'LICENSE-VECTORSCAN-APACHE', 'LICENSE-VECTORSCAN-MIT', 'THIRD_PARTY_NOTICES'];

function readManifest(directory) {
  return JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'));
}

function checkRelease(root, source = require('../package.json')) {
  root = path.resolve(root);
  const pkg = readManifest(root);
  const configuration = source.napi;
  assert.deepEqual([...configuration.targets].sort(), targets.map(target => target.target).sort());
  assert.equal(pkg.name, source.name, 'Staged package name must match the source SDK');
  assert.equal(pkg.version, source.version, 'Staged version must match the source SDK');
  assert.deepEqual(pkg.repository, source.repository, 'Staged repository must match the source SDK');
  assert.notEqual(pkg.private, true, 'Release staging must remove the source-only publishing guard');
  assert.equal(pkg.scripts, undefined, 'Release packages must not retain build/publishing scripts');
  assert.equal(pkg.devDependencies, undefined);
  assert.equal(pkg.napi, undefined);
  assert.deepEqual(Object.keys(pkg.optionalDependencies).sort(), targets.map(target => `${pkg.name}-${target.suffix}`).sort());
  for (const key of ['license', 'engines', 'exports', 'files']) assert.deepEqual(pkg[key], source[key], `Staged ${key} must match the SDK source`);
  assert.ok(!pkg.files.includes('PUBLISHING.md'), 'Do not ship the maintainer publishing runbook');
  assert.ok(!fs.existsSync(path.join(root, 'PUBLISHING.md')), 'Do not stage the maintainer publishing runbook');
  for (const notice of notices) {
    const expected = fs.readFileSync(path.join(__dirname, '..', notice));
    assert.ok(expected.length > 0, `Empty canonical notice: ${notice}`);
    assert.ok(fs.readFileSync(path.join(root, notice)).equals(expected), `Stale or modified root notice: ${notice}`);
  }
  const packages = [];
  for (const target of targets) {
    const name = `${pkg.name}-${target.suffix}`;
    assert.equal(pkg.optionalDependencies[name], pkg.version, `Missing exact optional dependency: ${name}`);
    const directory = path.join(root, 'npm', target.suffix);
    const metadata = readManifest(directory);
    assert.equal(metadata.name, name);
    assert.equal(metadata.version, pkg.version);
    assert.deepEqual(metadata.repository, pkg.repository);
    assert.equal(metadata.license, pkg.license);
    assert.deepEqual(metadata.engines, pkg.engines);
    assert.notEqual(metadata.private, true);
    assert.deepEqual(metadata.os, [target.os]);
    assert.deepEqual(metadata.cpu, [target.cpu]);
    if (target.libc) assert.deepEqual(metadata.libc, [target.libc]);
    const artifact = `${configuration.binaryName}.${target.suffix}.node`;
    assert.equal(metadata.main, artifact);
    const stat = fs.lstatSync(path.join(directory, artifact));
    assert.ok(stat.isFile() && stat.size > 0, `Missing regular native artifact: ${artifact}`);
    assert.equal(fs.readdirSync(directory).filter(name => name.endsWith('.node')).length, 1);
    assert.deepEqual(metadata.files, [artifact, 'README.md', ...notices], `Incomplete platform package files: ${name}`);
    assert.ok(fs.readFileSync(path.join(directory, 'README.md')).equals(
      fs.readFileSync(path.join(__dirname, '..', 'npm', target.suffix, 'README.md'))), `Missing or stale platform README: ${name}`);
    for (const notice of notices) {
      assert.ok(fs.readFileSync(path.join(directory, notice)).equals(fs.readFileSync(path.join(root, notice))),
        `Stale or modified notice ${notice} in ${name}`);
    }
    packages.push({ directory, manifest: metadata });
  }
  for (const file of ['index.cjs', 'index.mjs', 'index.d.ts', '_native.cjs', '_native.d.ts']) assert.ok(fs.statSync(path.join(root, file)).size > 0);
  for (const [subpath, entry] of Object.entries(pkg.exports)) {
    if (subpath === './package.json') continue;
    for (const file of Object.values(entry)) assert.ok(fs.statSync(path.join(root, file)).size > 0, `Missing export target: ${file}`);
  }
  packages.push({ directory: root, manifest: pkg }); // Exact dependencies must exist before the main package.
  return packages;
}

if (require.main === module) {
  const packages = checkRelease(process.argv[2] ?? path.join(__dirname, '../release'));
  const { name, version } = packages.at(-1).manifest;
  console.log(`Release artifacts complete for ${name}@${version}; this check does not publish.`);
}

module.exports = { checkRelease, readManifest, notices };
