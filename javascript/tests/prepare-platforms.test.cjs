'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const targets = require('../scripts/targets.cjs');
const pkg = require('../package.json');
const { notices } = require('../scripts/check-release.cjs');
const source = path.resolve(__dirname, '..');

function fixture(t) {
  const prefix = 'kingfisher-platform-prepare-';
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const root = path.join(temporary, 'package with spaces');
  fs.mkdirSync(path.join(root, 'scripts'), { recursive: true });
  t.after(() => {
    assert.equal(path.dirname(temporary), path.resolve(os.tmpdir()));
    assert.ok(path.basename(temporary).startsWith(prefix));
    fs.rmSync(temporary, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  for (const name of ['targets.cjs', 'prepare-platforms.cjs']) {
    fs.copyFileSync(path.join(source, 'scripts', name), path.join(root, 'scripts', name));
  }
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(pkg, null, 2) + '\r\n');
  for (const target of targets) {
    const directory = path.join(root, 'npm', target.suffix);
    fs.mkdirSync(directory, { recursive: true });
    fs.copyFileSync(path.join(source, 'npm', target.suffix, 'README.md'), path.join(directory, 'README.md'));
    fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify({ stale: target.suffix }));
    fs.writeFileSync(path.join(directory, `${pkg.napi.binaryName}.${target.suffix}.node`), `retained ${target.suffix}`);
    for (const name of notices) fs.writeFileSync(path.join(directory, name), `retained ${target.suffix} ${name}`);
  }
  return {
    root,
    run() {
      return spawnSync(process.execPath, [path.join(root, 'scripts/prepare-platforms.cjs')], {
        cwd: root, encoding: 'utf8', env: process.env,
      });
    },
    manifest(target) { return path.join(root, 'npm', target.suffix, 'package.json'); },
    configure(change) {
      const metadata = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
      change(metadata);
      fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify(metadata));
    },
  };
}

function success(result) { assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message); }
function manifests(value) { return targets.map(target => fs.readFileSync(value.manifest(target), 'utf8')); }

test('platform preparation creates six private metadata packages without napi or a native build', t => {
  const value = fixture(t);
  success(value.run());
  for (const target of targets) {
    const manifest = JSON.parse(fs.readFileSync(value.manifest(target), 'utf8'));
    const artifact = `${pkg.napi.binaryName}.${target.suffix}.node`;
    assert.equal(manifest.name, `${pkg.name}-${target.suffix}`);
    assert.equal(manifest.version, '1.0.1');
    assert.equal(manifest.private, true);
    assert.equal(manifest.main, artifact);
    assert.deepEqual(manifest.files, [artifact, 'README.md']);
    assert.deepEqual(manifest.os, [target.os]);
    assert.deepEqual(manifest.cpu, [target.cpu]);
    assert.deepEqual(manifest.libc, target.libc ? [target.libc] : undefined);
    for (const key of ['description', 'keywords', 'homepage', 'license', 'engines', 'repository', 'bugs']) {
      assert.deepEqual(manifest[key], pkg[key], key);
    }
    assert.equal(manifest.engines.node, '^22.13.0 || ^24.0.0 || ^26.0.0');
    assert.equal(manifest.scripts, undefined);
    assert.equal(manifest.dependencies, undefined);
    assert.equal(manifest.optionalDependencies, undefined);
  }
  const original = manifests(value);
  success(value.run());
  assert.deepEqual(manifests(value), original, 'Repeated preparation is byte-identical');
});

test('platform preparation preserves source guard, exact optional dependencies, prerequisites, artifacts and notices', t => {
  const value = fixture(t);
  const root = fs.readFileSync(path.join(value.root, 'package.json'));
  const originals = targets.flatMap(target => [
    'README.md', `${pkg.napi.binaryName}.${target.suffix}.node`, ...notices,
  ].map(name => {
    const file = path.join(value.root, 'npm', target.suffix, name);
    return { file, contents: fs.readFileSync(file) };
  }));
  success(value.run());
  assert.deepEqual(fs.readFileSync(path.join(value.root, 'package.json')), root);
  for (const { file, contents } of originals) assert.deepEqual(fs.readFileSync(file), contents, file);
  const metadata = JSON.parse(root);
  assert.equal(metadata.private, true);
  assert.equal(metadata.version, '1.0.1');
  assert.equal(Object.keys(metadata.exports).filter(key => key !== './package.json').length, 8);
  assert.equal(Object.keys(metadata.optionalDependencies).length, 6);
});

test('platform manifests can be recreated without replacing the required platform README', t => {
  const value = fixture(t);
  const file = value.manifest(targets[5]);
  assert.equal(path.dirname(file), path.join(value.root, 'npm', targets[5].suffix));
  fs.unlinkSync(file);
  success(value.run());
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).cpu[0], 'arm64');
});

test('incomplete, duplicate and unsupported target matrices fail before touching any platform metadata', t => {
  for (const change of [
    metadata => metadata.napi.targets.pop(),
    metadata => metadata.napi.targets.push(metadata.napi.targets[0]),
    metadata => metadata.napi.targets.push('x86_64-unknown-linux-musl'),
  ]) {
    const value = fixture(t);
    value.configure(change);
    const original = manifests(value);
    assert.notEqual(value.run().status, 0);
    assert.deepEqual(manifests(value), original);
  }
});

test('all six nonempty platform prerequisites must exist before any metadata is written', t => {
  for (const missing of [false, true]) {
    const value = fixture(t);
    const file = path.join(value.root, 'npm', targets[5].suffix, 'README.md');
    assert.equal(path.dirname(file), path.join(value.root, 'npm', targets[5].suffix));
    if (missing) fs.unlinkSync(file);
    else fs.writeFileSync(file, '');
    const original = manifests(value);
    assert.notEqual(value.run().status, 0);
    assert.deepEqual(manifests(value), original);
  }
});
