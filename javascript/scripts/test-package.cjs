'use strict';
// Install the sealed release tarballs into an unrelated project: no source tree, local .node
// fallback, registry publication, or consumer Rust build may be involved.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const targets = require('./targets.cjs');

const root = path.resolve(process.argv[2] ?? path.join(__dirname, '../release'));
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
assert.notEqual(pkg.private, true, 'Use the separate registry staging tree, not the development manifest');
const target = targets.find(target => target.os === process.platform && target.cpu === process.arch);
assert.ok(target, 'The packaging check requires a supported native host');
const npm = process.env.npm_execpath;
assert.ok(npm && fs.existsSync(npm), 'Run this check through npm run test:package');
const directory = fs.mkdtempSync(path.join(process.env.KINGFISHER_TEST_TMPDIR ?? os.tmpdir(), 'kingfisher-npm-check-'));
const env = { ...process.env };
delete env.NAPI_RS_NATIVE_LIBRARY_PATH;
delete env.NAPI_RS_FORCE_WASI;
try {
  const { readArchives } = require('./pack-release.cjs');
  const archives = readArchives(root);
  const main = archives.find(item => item.name === pkg.name).archive;
  const platform = archives.find(item => item.name === `${pkg.name}-${target.suffix}`).archive;
  const project = path.join(directory, 'consumer');
  fs.mkdirSync(project);
  fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'kingfisher-package-check', version: '0.0.0', private: true }));
  execFileSync(process.execPath, [npm, 'install', main, platform, '--ignore-scripts',
    '--offline', '--omit=optional', '--no-audit', '--no-fund'], { cwd: project, env, stdio: 'pipe' });
  const { notices } = require('./check-release.cjs');
  for (const name of [pkg.name, `${pkg.name}-${target.suffix}`]) {
    const installed = path.join(project, 'node_modules', name);
    for (const notice of notices) assert.deepEqual(fs.readFileSync(path.join(installed, notice)),
      fs.readFileSync(path.join(root, notice)), `Packed notice differs: ${name}/${notice}`);
    assert.ok(fs.statSync(path.join(installed, 'README.md')).size > 0);
    assert.ok(!fs.existsSync(path.join(installed, 'PUBLISHING.md')), 'Maintainer runbook leaked into consumer package');
  }
  // The host package is installed explicitly because names for other optional
  // platforms may not exist yet. Root dependencies still use exact registry versions.
  execFileSync(process.execPath, ['-e', `
    const assert = require('node:assert/strict');
    const sdk = require(${JSON.stringify(pkg.name)});
    assert.equal(sdk.version, ${JSON.stringify(pkg.version)});
    assert.equal(sdk.shannonEntropy('aabb'), 1);
    assert.ok(require.resolve(${JSON.stringify(`${pkg.name}-${target.suffix}`)}).endsWith('.node'));
    (async () => {
      const esm = await import(${JSON.stringify(pkg.name)});
      assert.equal(esm.Scanner, sdk.Scanner);
      assert.equal(esm.default, sdk);
      for (const name of ['core', 'rules', 'scanner', 'inputs', 'git', 'validation', 'revocation']) {
        const subpath = require(${JSON.stringify(pkg.name)} + '/' + name);
        const module = await import(${JSON.stringify(pkg.name)} + '/' + name);
        assert.equal(module.default, subpath);
        for (const [key, value] of Object.entries(subpath)) {
          assert.equal(value, sdk[key]);
          assert.equal(module[key], value);
        }
      }
      const rules = await sdk.Rules.load({ cache: false });
      const scanner = await sdk.Scanner.create({ rules });
      try { assert.equal((await scanner.scan('ordinary application configuration')).length, 0); }
      finally { await scanner.close(); }
    })().catch(error => { console.error(error); process.exitCode = 1; });
  `], { cwd: project, env, stdio: 'pipe' });
  console.log(`Clean tarball install passed for ${pkg.name}@${pkg.version} (${target.suffix}); nothing was published.`);
} finally {
  // Windows can briefly retain image/antimalware handles after the native
  // consumer exits. Retry only this owned fixture, and still fail if it stays locked.
  fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
