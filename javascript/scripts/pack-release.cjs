'use strict';
// Pack exactly once. Consumer tests and publication only read these archives;
// neither is allowed to silently repack a different set of bytes.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { checkRelease, notices } = require('./check-release.cjs');
const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
function integrity(bytes) { return `sha512-${crypto.createHash('sha512').update(bytes).digest('base64')}`; }
function archiveIntegrity(file) {
  const stat = fs.lstatSync(file);
  assert.ok(stat.isFile() && stat.size > 0 && stat.size <= MAX_ARCHIVE_BYTES,
    'Expected a nonempty regular npm archive within the size limit');
  return integrity(fs.readFileSync(file));
}
function npmCommand(args, options = {}) {
  const cli = process.env.npm_execpath;
  assert.ok(cli && fs.existsSync(cli), 'Run package commands through npm run');
  return execFileSync(process.execPath, [cli, ...args], options);
}
function packPackage(item, directory) {
  const [packed] = JSON.parse(npmCommand(['pack', item.directory, '--ignore-scripts', '--json',
    '--pack-destination', directory], { encoding: 'utf8' }));
  assert.equal(packed.name, item.manifest.name);
  assert.equal(packed.version, item.manifest.version);
  assert.equal(packed.filename, `${item.manifest.name}-${item.manifest.version}.tgz`);
  for (const file of ['README.md', ...notices]) assert.ok(packed.files.some(item => item.path === file), `Missing packed file: ${file}`);
  assert.ok(!packed.files.some(item => item.path === 'PUBLISHING.md'), 'Do not publish the maintainer runbook');
  const archive = path.join(directory, packed.filename);
  assert.equal(archiveIntegrity(archive), packed.integrity, 'Local npm archive integrity mismatch');
  return archive;
}
function readArchives(root, options = {}) {
  root = path.resolve(root);
  const packages = checkRelease(root, options.sourcePackage);
  const directory = path.join(root, 'archives');
  assert.ok(fs.lstatSync(directory).isDirectory(), 'Pack the release before testing or publication');
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json'), 'utf8'));
  assert.equal(manifest.schemaVersion, 1, 'Unknown archive manifest schema');
  assert.equal(manifest.packages.length, packages.length, 'Incomplete archive matrix');
  const result = packages.map((item, index) => {
    const archive = manifest.packages[index];
    assert.equal(archive.name, item.manifest.name, 'Archives must be platforms first, SDK last');
    assert.equal(archive.version, item.manifest.version);
    assert.equal(archive.filename, `${archive.name}-${archive.version}.tgz`, 'Unexpected archive path');
    const file = path.join(directory, archive.filename);
    assert.equal(archiveIntegrity(file), archive.integrity, `Tested archive changed: ${archive.name}`);
    return { ...archive, archive: file };
  });
  assert.deepEqual(fs.readdirSync(directory).sort(), ['manifest.json', ...result.map(item => item.filename)].sort(), 'Unexpected files in archive directory');
  return result;
}
function packRelease(root, options = {}) {
  root = path.resolve(root);
  const packages = checkRelease(root, options.sourcePackage);
  const destination = path.join(root, 'archives');
  // Repeated invocations validate the originals, never rewrite them. Restage the
  // release explicitly when preparing a genuinely different build.
  if (fs.existsSync(destination)) return readArchives(root, options);
  const directory = fs.mkdtempSync(path.join(root, '.archives-stage-'));
  try {
    const packed = packages.map(item => {
      const file = (options.pack ?? packPackage)(item, directory);
      assert.equal(path.dirname(file), directory, 'Archive must remain inside the owned packing directory');
      return { name: item.manifest.name, version: item.manifest.version,
        filename: path.basename(file), integrity: archiveIntegrity(file) };
    });
    fs.writeFileSync(path.join(directory, 'manifest.json'), JSON.stringify({ schemaVersion: 1, packages: packed }, null, 2) + '\n');
    assert.equal(path.resolve(destination), path.join(root, 'archives'));
    assert.equal(path.dirname(directory), root);
    assert.ok(path.basename(directory).startsWith('.archives-stage-'));
    fs.renameSync(directory, destination);
  } finally {
    assert.equal(path.dirname(directory), root);
    assert.ok(path.basename(directory).startsWith('.archives-stage-'));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
  return readArchives(root, options);
}
if (require.main === module) {
  const archives = packRelease(process.argv[2] ?? path.join(__dirname, '../release'));
  console.log(`Packed and sealed ${archives.length} exact release archives; nothing was published.`);
}
module.exports = { packRelease, readArchives, packPackage, integrity, archiveIntegrity, npmCommand, MAX_ARCHIVE_BYTES };
