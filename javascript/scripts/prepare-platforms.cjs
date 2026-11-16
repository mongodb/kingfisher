'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const targets = require('./targets.cjs');
const root = path.resolve(__dirname, '..');
const source = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const configuration = source.napi;
assert.deepEqual([...configuration.targets].sort(), targets.map(target => target.target).sort(),
  'Platform preparation requires exactly the six supported native SDK targets');
assert.equal(typeof configuration.binaryName, 'string');
assert.ok(configuration.binaryName.length > 0 && !/[\\/\0]/.test(configuration.binaryName) &&
  !['.', '..'].includes(configuration.binaryName), 'Native binary name must be a single path segment');

// Preflight every hand-maintained platform prerequisite before writing any
// metadata. Never replace the architecture/runtime READMEs with generic text.
const packages = targets.map(target => {
  const directory = path.join(root, 'npm', target.suffix);
  assert.ok(fs.lstatSync(directory).isDirectory(), `Expected platform directory: ${target.suffix}`);
  const readme = fs.lstatSync(path.join(directory, 'README.md'));
  assert.ok(readme.isFile() && readme.size > 0, `Missing platform prerequisites: ${target.suffix}`);
  const file = path.join(directory, 'package.json');
  if (fs.existsSync(file)) assert.ok(fs.lstatSync(file).isFile(), `Expected regular platform manifest: ${target.suffix}`);
  const artifact = `${configuration.binaryName}.${target.suffix}.node`;
  const manifest = {
    name: `${source.name}-${target.suffix}`, version: source.version,
    cpu: [target.cpu], main: artifact, files: [artifact, 'README.md'],
  };
  for (const key of ['description', 'keywords', 'author', 'authors', 'homepage', 'license', 'engines', 'repository', 'bugs']) {
    if (source[key] !== undefined) manifest[key] = source[key];
  }
  if (source.publishConfig) {
    manifest.publishConfig = Object.fromEntries(['registry', 'access']
      .filter(key => source.publishConfig[key] !== undefined).map(key => [key, source.publishConfig[key]]));
  }
  manifest.os = [target.os];
  if (target.libc) manifest.libc = [target.libc];
  manifest.private = true; // Only checked release staging removes publishing guards.
  return { file, manifest };
});
for (const { file, manifest } of packages) fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
// Source optional dependencies stay local; artifacts, notices and prerequisites
// are untouched. Release collection still requires and verifies all six builds.
