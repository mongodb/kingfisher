'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const source = path.resolve(__dirname, '..');
const targets = require('../scripts/targets.cjs');
const pkg = require('../package.json');
const { fixture, run, success, cleanup } = require('./package-fixture.cjs');

test('artifact collection requires a complete matrix before changing manifests', () => {
  const value = fixture();
  try {
    const manifest = path.join(value.root, 'npm', targets[0].suffix, 'package.json');
    const original = fs.readFileSync(manifest);
    fs.unlinkSync(path.join(value.artifacts, `${pkg.napi.binaryName}.${targets[1].suffix}.node`));
    assert.notEqual(run(value.root, 'collect-artifacts.cjs').status, 0);
    assert.deepEqual(fs.readFileSync(manifest), original);
    assert.equal(fs.existsSync(path.join(value.root, 'release')), false);
  } finally { cleanup(value); }
});

test('registry staging removes development settings and preserves all export and license files', () => {
  const value = fixture();
  try {
    const sourceManifest = path.join(value.root, 'npm', targets[0].suffix, 'package.json');
    const original = fs.readFileSync(sourceManifest);
    success(run(value.root, 'collect-artifacts.cjs'));
    success(run(value.root, 'check-release.cjs'));
    const staged = JSON.parse(fs.readFileSync(path.join(value.root, 'release', 'package.json'), 'utf8'));
    assert.equal(staged.private, undefined);
    assert.equal(staged.scripts, undefined);
    assert.equal(staged.devDependencies, undefined);
    assert.ok(Object.values(staged.optionalDependencies).every(version => version === pkg.version));
    assert.equal(JSON.parse(fs.readFileSync(path.join(value.root, 'package.json'))).private, true);
    assert.deepEqual(fs.readFileSync(sourceManifest), original, 'Collection must not alter development manifests');
    staged.optionalDependencies[`${pkg.name}-${targets[0].suffix}`] = `file:./npm/${targets[0].suffix}`;
    fs.writeFileSync(path.join(value.root, 'release', 'package.json'), JSON.stringify(staged));
    assert.notEqual(run(value.root, 'check-release.cjs').status, 0);
  } finally { cleanup(value); }
});

test('repeated collection removes stale staged files and ignores development package leftovers', () => {
  const value = fixture();
  try {
    success(run(value.root, 'collect-artifacts.cjs'));
    const release = path.join(value.root, 'release');
    const leftovers = ['examples/removed-example.mjs', 'lib/removed-module.cjs', `npm/${targets[0].suffix}/old-addon.node`];
    for (const file of leftovers) fs.writeFileSync(path.join(release, file), 'stale staging content');
    fs.writeFileSync(path.join(value.root, 'npm', targets[0].suffix, 'development-leftover.node'), 'not a tested artifact');
    success(run(value.root, 'collect-artifacts.cjs'));
    success(run(value.root, 'check-release.cjs'));
    for (const file of leftovers) assert.equal(fs.existsSync(path.join(release, file)), false);
    assert.equal(fs.existsSync(path.join(release, 'npm', targets[0].suffix, 'development-leftover.node')), false);
    assert.ok(!fs.readdirSync(value.root).some(file => file.startsWith('.release-stage-')));
  } finally { cleanup(value); }
});

test('incomplete source exports preserve a previously staged release', () => {
  const value = fixture();
  try {
    success(run(value.root, 'collect-artifacts.cjs'));
    const manifest = path.join(value.root, 'release', 'package.json');
    const previous = fs.readFileSync(manifest);
    fs.unlinkSync(path.join(value.root, 'index.mjs'));
    assert.notEqual(run(value.root, 'collect-artifacts.cjs').status, 0);
    assert.deepEqual(fs.readFileSync(manifest), previous);
    success(run(value.root, 'check-release.cjs'));
    assert.ok(!fs.readdirSync(value.root).some(file => file.startsWith('.release-stage-')));
  } finally { cleanup(value); }
});

test('release checks reject license files omitted from a platform tarball', () => {
  const value = fixture();
  try {
    success(run(value.root, 'collect-artifacts.cjs'));
    const file = path.join(value.root, 'release', 'npm', targets[0].suffix, 'package.json');
    const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
    manifest.files = manifest.files.filter(file => file !== 'LICENSE-RULES');
    fs.writeFileSync(file, JSON.stringify(manifest));
    assert.notEqual(run(value.root, 'check-release.cjs').status, 0);
  } finally { cleanup(value); }
});

test('release checks reject altered legal text even when every staged copy agrees', () => {
  const value = fixture();
  try {
    success(run(value.root, 'collect-artifacts.cjs'));
    const release = path.join(value.root, 'release');
    const directories = [release, ...targets.map(target => path.join(release, 'npm', target.suffix))];
    for (const directory of directories) fs.writeFileSync(path.join(directory, 'THIRD_PARTY_NOTICES'), 'nonempty but legally incomplete');
    const result = run(value.root, 'check-release.cjs');
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Stale or modified root notice/);
  } finally { cleanup(value); }
});

test('platform packages must include the documented README and exclude maintainer publishing instructions', () => {
  const value = fixture();
  try {
    success(run(value.root, 'collect-artifacts.cjs'));
    const release = path.join(value.root, 'release');
    const readme = path.join(release, 'npm', targets[0].suffix, 'README.md');
    fs.writeFileSync(readme, 'generic generated README');
    assert.notEqual(run(value.root, 'check-release.cjs').status, 0);
    success(run(value.root, 'collect-artifacts.cjs'));
    assert.ok(!fs.existsSync(path.join(release, 'PUBLISHING.md')));
    fs.copyFileSync(path.join(value.root, 'PUBLISHING.md'), path.join(release, 'PUBLISHING.md'));
    assert.notEqual(run(value.root, 'check-release.cjs').status, 0);
  } finally { cleanup(value); }
});

test('fresh npm tarballs load the genuine host addon without a source-tree fallback', () => {
  const value = fixture();
  try {
    const target = targets.find(target => target.os === process.platform && target.cpu === process.arch);
    assert.ok(target, 'Packaging tests require a supported native host');
    const name = `${pkg.napi.binaryName}.${target.suffix}.node`;
    fs.copyFileSync(path.join(source, name), path.join(value.artifacts, name));
    success(run(value.root, 'collect-artifacts.cjs'));
    success(run(value.root, 'pack-release.cjs'));
    success(run(value.root, 'test-package.cjs'));
  } finally { cleanup(value); }
});

test('release checks reject versions and repositories inconsistent with SDK source', () => {
  const value = fixture();
  try {
    success(run(value.root, 'collect-artifacts.cjs'));
    const file = path.join(value.root, 'release', 'package.json');
    const original = fs.readFileSync(file);
    for (const change of [{ version: '9.9.9' }, { repository: { type: 'git', url: 'https://github.com/other/repo.git' } }]) {
      const manifest = { ...JSON.parse(original), ...change };
      fs.writeFileSync(file, JSON.stringify(manifest));
      assert.notEqual(run(value.root, 'check-release.cjs').status, 0);
    }
  } finally { cleanup(value); }
});
