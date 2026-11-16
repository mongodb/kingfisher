'use strict';
// Planning is read-only with respect to registries. Only --publish can upload,
// and it requires a validated release event on GitHub-hosted OIDC. The central
// coordinator is responsible for source ancestry and the all-builds-ready gate.
const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { checkRelease, readManifest } = require('./check-release.cjs');
const { readArchives, packPackage, integrity, archiveIntegrity, npmCommand, MAX_ARCHIVE_BYTES } = require('./pack-release.cjs');

const REGISTRY = 'https://registry.npmjs.org/';

async function responseBytes(response, limit) {
  const contentLength = response.headers.get('content-length');
  if (contentLength !== null && Number(contentLength) > limit) {
    await response.body?.cancel();
    throw new Error('Registry response exceeds the size limit');
  }
  assert.ok(response.body, 'Registry returned an empty response');
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) {
        await reader.cancel();
        throw new Error('Registry response exceeds the size limit');
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks, total);
  } finally { reader.releaseLock(); }
}

async function request(url, fetcher) {
  return await fetcher(url, { redirect: 'error', signal: AbortSignal.timeout(60_000) });
}

function githubRepository(manifest) {
  const url = new URL(manifest.repository.url.replace(/^git\+/, ''));
  assert.equal(url.protocol, 'https:');
  assert.equal(url.hostname, 'github.com', 'npm OIDC publishing requires GitHub repository metadata');
  assert.equal(url.username + url.password, '', 'Repository metadata must not contain credentials');
  const repository = url.pathname.replace(/^\//, '').replace(/\.git\/?$/, '').replace(/\/$/, '');
  assert.match(repository, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
  return repository;
}

function newerCoreVersion(remote, local) {
  const match = typeof remote === 'string' && remote.length <= 256 &&
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/.exec(remote);
  assert.ok(match && match[0] === remote && (!match[4] || match[4].split('.').every(value => value && !/^0\d+$/.test(value))) &&
    (!match[5] || match[5].split('.').every(Boolean)), `Invalid registry latest version: ${remote}`);
  const current = local.split(/[+-]/, 1)[0].split('.').map(BigInt);
  for (let index = 0; index < 3; index++) {
    const value = BigInt(match[index + 1]);
    if (value !== current[index]) return value > current[index];
  }
  return false;
}

async function createPlan(releaseRoot, options = {}) {
  const packages = checkRelease(releaseRoot, options.sourcePackage);
  const main = packages.at(-1).manifest;
  const registry = new URL(options.registryURL ?? REGISTRY);
  const fetcher = options.fetch ?? fetch;
  const archives = readArchives(releaseRoot, options);
  const plan = {
    repository: githubRepository(main),
    version: main.version,
    distTag: main.version.includes('-') ? 'next' : 'latest',
    packages: [],
  };

  // Inspect EVERY previously tested archive before permitting ANY upload.
  plan.packages = archives.map(item => ({ name: item.name, version: item.version,
    archive: item.archive, integrity: item.integrity, action: 'publish' }));
  if (!main.version.includes('-')) {
    for (const item of plan.packages) {
      const response = await request(new URL(`${encodeURIComponent(item.name)}/latest`, registry), fetcher);
      if (response.status === 404) { await response.body?.cancel(); continue; }
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`Registry latest lookup failed (${response.status}) for ${item.name}`);
      }
      const remote = JSON.parse((await responseBytes(response, 1024 * 1024)).toString('utf8'));
      assert.equal(remote.name, item.name, 'Registry latest package name mismatch');
      if (newerCoreVersion(remote.version, main.version)) {
        // npm publish defaults to latest. An older maintenance release must use
        // a non-semver tag rather than silently downgrading consumers.
        plan.distTag = `backport-${main.version.split('.').slice(0, 2).join('.')}`;
      }
    }
  }
  for (const item of plan.packages) {
    const url = new URL(`${encodeURIComponent(item.name)}/${encodeURIComponent(item.version)}`, registry);
    const response = await request(url, fetcher);
    if (response.status === 404) {
      await response.body?.cancel();
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel();
      throw new Error(`Registry lookup failed (${response.status}) for ${item.name}`);
    }
    const remote = JSON.parse((await responseBytes(response, 1024 * 1024)).toString('utf8'));
    assert.equal(remote.name, item.name, 'Registry package name mismatch');
    assert.equal(remote.version, item.version, 'Registry package version mismatch');
    assert.equal(remote.dist?.integrity, item.integrity,
      `Published bytes differ: ${item.name}@${item.version}; use a new SDK version`);
    const tarball = new URL(remote.dist.tarball);
    assert.equal(tarball.origin, registry.origin, 'Registry tarball must stay on the same origin');
    assert.equal(tarball.username + tarball.password, '', 'Registry tarball must not contain credentials');
    const archiveResponse = await request(tarball, fetcher);
    if (!archiveResponse.ok) {
      await archiveResponse.body?.cancel();
      throw new Error(`Published archive download failed (${archiveResponse.status}) for ${item.name}`);
    }
    assert.equal(integrity(await responseBytes(archiveResponse, MAX_ARCHIVE_BYTES)), item.integrity,
      `Published archive integrity mismatch: ${item.name}@${item.version}`);
    item.action = 'skip';
  }
  return plan;
}

function releaseGit(args) {
  return childProcess.execFileSync('git', args, {
    cwd: path.resolve(__dirname, '../..'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function stableCargoVersion(relative, revision) {
  // Only the package table counts: dependency versions cannot authorize a tag.
  const manifest = revision ? releaseGit(['show', `${revision}:${relative}`])
    : fs.readFileSync(path.resolve(__dirname, '../..', relative), 'utf8');
  const table = /^[ \t]*\[package\][ \t]*(?:#.*)?\r?\n([\s\S]*?)(?=^[ \t]*\[|$(?![\s\S]))/m.exec(manifest)?.[1];
  const version = table && /^[ \t]*version[ \t]*=[ \t]*(["'])((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\1[ \t]*(?:#.*)?\r?$/m.exec(table)?.[2];
  assert.ok(version, `Release source requires a stable package version: ${relative}`);
  return version;
}

function checkPublishEnvironment(plan, env = process.env) {
  assert.equal(env.GITHUB_ACTIONS, 'true', 'Publishing requires GitHub Actions');
  assert.equal(env.RUNNER_ENVIRONMENT, 'github-hosted', 'Publishing requires a GitHub-hosted runner');
  assert.equal(plan.repository, 'mongodb/kingfisher', 'Publishing requires the upstream repository');
  assert.equal(env.GITHUB_REPOSITORY, plan.repository, 'Publishing repository does not match package metadata');
  const manual = env.GITHUB_EVENT_NAME === 'workflow_dispatch';
  assert.ok(env.GITHUB_EVENT_NAME === 'push' || manual, 'Publishing requires an authorized release event');
  let manualCliVersion;
  if (manual) {
    assert.equal(env.KINGFISHER_RELEASE_PUBLISH, 'true', 'Manual publication requires explicit authorization');
    if (env.GITHUB_REF === 'refs/heads/main') {
      assert.equal(env.KINGFISHER_RELEASE_EXPECTED_SHA?.length, 40,
        'Manual publication requires a full expected SHA');
      assert.match(env.KINGFISHER_RELEASE_EXPECTED_SHA, /^[0-9a-f]{40}$/,
        'Manual publication requires a full expected SHA');
      assert.notEqual(env.KINGFISHER_RELEASE_EXPECTED_SHA, '0'.repeat(40));
      assert.equal(env.GITHUB_SHA, env.KINGFISHER_RELEASE_EXPECTED_SHA,
        'Manual publication must match the pinned expected SHA');
    } else {
      const coordinatedNpm = env.KINGFISHER_RELEASE_COHORT === 'true'
        && env.GITHUB_REF?.startsWith('refs/tags/npm-v');
      assert.ok(coordinatedNpm || env.GITHUB_REF?.startsWith('refs/tags/v'),
        'Manual publication requires main, an exact CLI tag, or a verified npm cohort');
      assert.equal(env.GITHUB_SHA?.length, 40, 'Manual tag publication requires a full source SHA');
      assert.match(env.GITHUB_SHA, /^[0-9a-f]{40}$/, 'Manual tag publication requires a full source SHA');
      assert.notEqual(env.GITHUB_SHA, '0'.repeat(40));
      assert.equal(releaseGit(['rev-parse', 'HEAD']), env.GITHUB_SHA,
        'Manual tag publication must match the pinned checkout SHA');
      if (coordinatedNpm) {
        assert.equal(env.GITHUB_WORKFLOW_REF,
          `mongodb/kingfisher/.github/workflows/node-sdk.yml@${env.GITHUB_REF}`,
          'Coordinated npm publication must retain the original trusted workflow');
        assert.equal(env.GITHUB_SHA, env.KINGFISHER_RELEASE_EXPECTED_SHA,
          'Coordinated npm publication must match the tested source SHA');
      } else {
        manualCliVersion = stableCargoVersion('Cargo.toml', env.GITHUB_SHA);
      }
    }
  }
  if (env.GITHUB_REF === 'refs/heads/main') {
    assert.equal(env.GITHUB_REF_TYPE, 'branch', 'Publishing requires the main branch');
    assert.equal(env.GITHUB_REF_NAME, 'main', 'Publishing requires the main branch');
  } else {
    assert.equal(env.GITHUB_REF_TYPE, 'tag', 'Publishing requires main or a validated release tag');
    assert.equal(env.GITHUB_REF, `refs/tags/${env.GITHUB_REF_NAME}`, 'Publishing requires an exact release ref');
    if (env.GITHUB_REF_NAME?.startsWith('npm-v')) {
      assert.equal(env.GITHUB_REF_NAME, `npm-v${plan.version}`, 'SDK tag must match the staged version');
    } else if (env.GITHUB_REF_NAME?.startsWith('python-v')) {
      assert.equal(env.GITHUB_REF_NAME, `python-v${stableCargoVersion('crates/kingfisher-python/Cargo.toml')}`,
        'Python release tag must match its source manifest');
    } else {
      assert.equal(env.GITHUB_REF_NAME, `v${manualCliVersion ?? stableCargoVersion('Cargo.toml')}`,
        'CLI release tag must match its source manifest');
    }
  }
  assert.ok(env.ACTIONS_ID_TOKEN_REQUEST_URL && env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
    'Publishing requires id-token: write for GitHub OIDC');
}

function publishPlan(plan, options = {}) {
  checkPublishEnvironment(plan, options.env);
  // A plan is not authorization to upload a subsequently changed local file.
  for (const item of plan.packages) {
    assert.ok(['publish', 'skip'].includes(item.action), 'Unknown publication action');
    assert.equal(archiveIntegrity(item.archive), item.integrity, `Local archive changed: ${item.name}`);
  }
  const run = options.run ?? (item => npmCommand(['publish', item.archive,
    '--access', 'public', '--ignore-scripts', '--registry', REGISTRY,
    '--tag', plan.distTag], { stdio: 'inherit' }));
  for (const item of plan.packages) {
    if (item.action === 'skip') continue; // Never rewrite existing versions or dist-tags.
    run(item, plan.distTag);
  }
}

async function main(argv = process.argv.slice(2)) {
  let releaseRoot = path.resolve(__dirname, '../release');
  let publish = false;
  let json = false;
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--publish') publish = true;
    else if (arg === '--json') json = true;
    else if (arg === '--root' && argv[index + 1]) releaseRoot = path.resolve(argv[++index]);
    else throw new Error(`Unknown or incomplete argument: ${arg}`);
  }
  if (publish) {
    const manifest = readManifest(releaseRoot);
    checkPublishEnvironment({ repository: githubRepository(manifest), version: manifest.version });
  }
  const plan = await createPlan(releaseRoot);
  if (json) console.log(JSON.stringify(plan, null, 2));
  else {
    console.log(`Selected npm dist-tag: ${plan.distTag}`);
    for (const item of plan.packages) console.log(`${item.name}@${item.version}: ${item.action}`);
  }
  if (publish) publishPlan(plan);
  else console.log('Read-only publication plan; no packages were uploaded.');
}

if (require.main === module) {
  main().catch(error => { console.error(error.message); process.exitCode = 1; });
}

module.exports = { createPlan, publishPlan, checkPublishEnvironment, integrity, packPackage };
