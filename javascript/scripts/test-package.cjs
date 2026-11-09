'use strict';
// Install the sealed release tarballs into an unrelated project: no source tree, local .node
// fallback, registry publication, or consumer Rust build may be involved.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const targets = require('./targets.cjs');

async function main() {
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
  // A clean consumer is not a worker of the outer Node test runner.
  delete env.NODE_TEST_CONTEXT;
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
    // The showcase is part of the public package, not a checkout-only screenshot.
    // Check the installed tarball so npm ignore rules cannot silently drop assets.
    const showcase = path.join(project, 'node_modules', pkg.name, 'examples', 'kingfisher-workbench');
    for (const file of ['README.md', 'package.json', 'src/main.mjs', 'src/agent.mjs',
      'src/args.mjs', 'src/progress.mjs', 'src/safety.mjs', 'src/server.mjs',
      'src/report.mjs', 'src/sdk.mjs', 'demo/run.mjs', 'demo/mock-provider.mjs',
      'demo/fixture.mjs', 'demo/fixture/config.env', 'demo/acme-rule.yml',
      'scripts/checkout.mjs', 'scripts/check.mjs', 'test/report.test.mjs',
      'screenshots/report-overview.png', 'screenshots/report-revocation.png']) {
      assert.ok(fs.statSync(path.join(showcase, file)).size > 0, `Missing packed showcase file: ${file}`);
    }
    // Relative documentation links must work from the installed package, not
    // merely from a repository checkout containing the root docs/ directory.
    const installedSdk = path.join(project, 'node_modules', pkg.name);
    for (const relative of ['README.md', 'examples/README.md', 'examples/kingfisher-workbench/README.md']) {
      const readme = path.join(installedSdk, relative);
      const links = fs.readFileSync(readme, 'utf8').matchAll(/!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))\)/g);
      for (const [, angled, plain] of links) {
        const target = angled ?? plain;
        if (/^(?:[a-z][a-z\d+.-]*:|#)/i.test(target)) continue;
        const resolved = path.resolve(path.dirname(readme), decodeURIComponent(target.split('#')[0]));
        const local = path.relative(installedSdk, resolved);
        assert.ok(!path.isAbsolute(local) && local !== '..' && !local.startsWith(`..${path.sep}`),
          `Packed README link escapes the package: ${relative} -> ${target}`);
        assert.ok(fs.existsSync(resolved), `Broken packed README link: ${relative} -> ${target}`);
      }
    }
    const showcasePkg = JSON.parse(fs.readFileSync(path.join(showcase, 'package.json'), 'utf8'));
    assert.equal(showcasePkg.name, 'kingfisher-workbench-example');
    assert.equal(showcasePkg.private, true);
    const input = path.join(directory, 'synthetic scan with spaces');
    fs.mkdirSync(input);
    const token = 'ghp_aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6';
    fs.writeFileSync(path.join(input, 'config.env'), `GITHUB_TOKEN=${token}\n`);
    const html = path.join(directory, 'report.html');
    const json = path.join(directory, 'report.json');
    const showcaseEnv = { ...env };
    delete showcaseEnv.KINGFISHER_WORKBENCH_SDK;
    execFileSync(process.execPath, [path.join(showcase, 'src', 'main.mjs'), input,
      '--out', html, '--json', json, '--no-serve', '--no-git-history', '--quiet'], {
      cwd: project, env: showcaseEnv, stdio: 'pipe', timeout: 120_000,
    });
    const report = JSON.parse(fs.readFileSync(json, 'utf8'));
    const snapshot = fs.readFileSync(html, 'utf8');
    assert.match(snapshot, /<title>Kingfisher Workbench — /);
    assert.match(snapshot, /<h1>Kingfisher Workbench<\/h1>/);
    assert.equal(report.meta.version, pkg.version);
    assert.equal(report.meta.validate, false, 'Installed showcase detection must stay offline');
    assert.equal(report.meta.revokeEnabled, false);
    assert.ok(report.entries.some(entry => entry.finding.ruleId === 'betterleaks.github-pat'));
    assert.ok(report.entries.every(entry => entry.finding.secret === '[REDACTED]'));
    for (const output of [html, json]) {
      const text = fs.readFileSync(output, 'utf8');
      assert.ok(!text.includes(token), 'Packed showcase exported a raw credential');
      assert.ok(!text.includes('dedupeKey'), 'Private credential digests must not be exported');
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
  } finally {
    // Async removal honors Windows retries; Node 24.0's native rmSync does not.
    // Retry only this owned fixture, and still fail if it stays locked.
    await fs.promises.rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
  console.log(`Clean tarball install passed for ${pkg.name}@${pkg.version} (${target.suffix}); nothing was published.`);
}

main().catch(error => { console.error(error); process.exitCode = 1; });
