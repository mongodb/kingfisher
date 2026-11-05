'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const source = path.resolve(__dirname, '..');
const targets = require('../scripts/targets.cjs');
const pkg = require('../package.json');
const { temporary } = require('./helpers.cjs');

function fixture() {
  const directory = temporary();
  const root = path.join(directory, 'javascript package with spaces');
  fs.mkdirSync(root);
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    if (entry.isFile() && (/\.(?:cjs|mjs|d\.ts)$/.test(entry.name) || /^(?:LICENSE|NOTICE)/.test(entry.name)
      || ['package.json', 'README.md', 'PUBLISHING.md', 'THIRD_PARTY_NOTICES'].includes(entry.name))) {
      fs.copyFileSync(path.join(source, entry.name), path.join(root, entry.name));
    }
  }
  for (const name of ['scripts', 'lib', 'examples']) fs.cpSync(path.join(source, name), path.join(root, name), { recursive: true });
  const artifacts = path.join(root, 'artifacts');
  fs.mkdirSync(artifacts);
  for (const target of targets) {
    const platform = path.join(root, 'npm', target.suffix);
    fs.mkdirSync(platform, { recursive: true });
    for (const name of ['package.json', 'README.md']) fs.copyFileSync(path.join(source, 'npm', target.suffix, name), path.join(platform, name));
    // Matrix fixtures test staging policy only, never non-host native code.
    fs.writeFileSync(path.join(artifacts, `${pkg.napi.binaryName}.${target.suffix}.node`), 'staging-policy-fixture');
  }
  return { directory, root, artifacts };
}

function run(root, script, args = []) {
  return spawnSync(process.execPath, [path.join(root, 'scripts', script), ...args], {
    cwd: root, encoding: 'utf8', env: process.env,
  });
}
function success(result) {
  assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
}
function cleanup(value) {
  fs.rmSync(value.directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}

module.exports = { fixture, run, success, cleanup };
