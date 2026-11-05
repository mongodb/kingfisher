'use strict';
const fs = require('node:fs');
const path = require('node:path');
const pkg = require('../package.json');
const targets = require('./targets.cjs');
const { checkRelease, notices } = require('./check-release.cjs');
const root = path.resolve(__dirname, '..');
const directory = path.resolve(process.argv[2] ?? path.join(root, 'artifacts'));
const sources = new Map();
function walk(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const file = path.join(directory, entry.name);
    if (entry.isDirectory()) walk(file);
    else if (entry.isFile() && entry.name.endsWith('.node')) {
      if (sources.has(entry.name)) throw new Error(`Duplicate artifact: ${entry.name}`);
      sources.set(entry.name, file);
    }
  }
}
walk(directory);
// Preflight the complete matrix before modifying any local package or staging.
if (sources.size !== targets.length) throw new Error('Expected exactly one native artifact for every release target');
for (const target of targets) {
  const name = `${pkg.napi.binaryName}.${target.suffix}.node`;
  if (!sources.has(name)) throw new Error(`Missing tested artifact: ${name}`);
  if (fs.statSync(sources.get(name)).size === 0) throw new Error(`Empty native artifact: ${name}`);
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'npm', target.suffix, 'package.json'), 'utf8'));
  if (manifest.name !== `${pkg.name}-${target.suffix}` || manifest.version !== pkg.version) {
    throw new Error(`Platform manifest version/name mismatch: ${target.suffix}`);
  }
}
for (const notice of notices) {
  if (fs.statSync(path.join(root, notice)).size === 0) throw new Error(`Empty license/notice: ${notice}`);
}
const release = path.join(root, 'release');
// Build in a fresh owned directory: deleted examples and old platform binaries
// must never survive a second collection into the publishable tree.
const staging = fs.mkdtempSync(path.join(root, '.release-stage-'));
try {
  for (const target of targets) {
    const name = `${pkg.napi.binaryName}.${target.suffix}.node`;
    const destination = path.join(staging, 'npm', target.suffix);
    fs.mkdirSync(destination, { recursive: true });
    const manifest = JSON.parse(fs.readFileSync(path.join(root, 'npm', target.suffix, 'package.json'), 'utf8'));
    manifest.files = [name, 'README.md', ...notices];
    delete manifest.private;
    fs.writeFileSync(path.join(destination, 'package.json'), JSON.stringify(manifest, null, 2) + '\n');
    fs.copyFileSync(sources.get(name), path.join(destination, name));
    fs.copyFileSync(path.join(root, 'npm', target.suffix, 'README.md'), path.join(destination, 'README.md'));
    for (const notice of notices) fs.copyFileSync(path.join(root, notice), path.join(destination, notice));
  }
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.isFile() && (/\.(?:cjs|mjs|d\.ts)$/.test(entry.name) || notices.includes(entry.name) || entry.name === 'README.md')) {
      fs.copyFileSync(path.join(root, entry.name), path.join(staging, entry.name));
    }
  }
  for (const directory of ['lib', 'examples']) fs.cpSync(path.join(root, directory), path.join(staging, directory), { recursive: true });
  const manifest = { ...pkg, optionalDependencies: Object.fromEntries(targets.map(target => [`${pkg.name}-${target.suffix}`, pkg.version])) };
  delete manifest.scripts;
  delete manifest.devDependencies;
  delete manifest.napi;
  delete manifest.private;
  fs.writeFileSync(path.join(staging, 'package.json'), JSON.stringify(manifest, null, 2) + '\n');
  checkRelease(staging, pkg); // Preserve the previous tree if any source is incomplete.
  if (fs.existsSync(release) && !fs.lstatSync(release).isDirectory()) throw new Error('Expected release staging to be a directory');
  // Both absolute paths are fixed children of the SDK root, never caller paths.
  fs.rmSync(release, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  fs.renameSync(staging, release);
} finally {
  fs.rmSync(staging, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
console.log(`Staged exact-version registry packages in ${release}; nothing was published.`);
