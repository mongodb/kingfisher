'use strict';
const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const pkg = require('../package.json');
const { server } = require('./helpers.cjs');
const { fixture, run, success, cleanup } = require('./package-fixture.cjs');
const { checkRelease } = require('../scripts/check-release.cjs');
const { createPlan, publishPlan, checkPublishEnvironment, integrity, packPackage } = require('../scripts/publish-packages.cjs');
const { packRelease, readArchives } = require('../scripts/pack-release.cjs');

function stagedFixture(packages = pack) {
  const value = fixture();
  success(run(value.root, 'collect-artifacts.cjs'));
  value.release = path.join(value.root, 'release');
  packRelease(value.release, { pack: packages });
  value.archives = path.join(value.release, 'archives');
  return value;
}
function bytesFor(name) { return Buffer.from(`package-archive-fixture:${name}`); }
function pack(item, directory) {
  const archive = path.join(directory, `${item.manifest.name}-${item.manifest.version}.tgz`);
  fs.writeFileSync(archive, bytesFor(item.manifest.name));
  return archive;
}
function environment(overrides = {}) {
  return { GITHUB_ACTIONS: 'true', GITHUB_EVENT_NAME: 'push', RUNNER_ENVIRONMENT: 'github-hosted',
    GITHUB_REPOSITORY: 'mongodb/kingfisher', GITHUB_REF_TYPE: 'tag',
    GITHUB_REF_NAME: `npm-v${pkg.version}`, GITHUB_REF: `refs/tags/npm-v${pkg.version}`,
    ACTIONS_ID_TOKEN_REQUEST_URL: 'https://example.invalid/oidc',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'synthetic-test-token', ...overrides };
}
async function registry(entries = new Map(), options = {}) {
  let mock;
  const requests = [];
  mock = await server((request, response) => {
    requests.push({ method: request.method, path: request.url });
    const parts = request.url.split('/').filter(Boolean).map(decodeURIComponent);
    if (parts[0] === 'archives') {
      const name = parts[1].replace(/\.tgz$/, '');
      response.end(entries.get(name).download ?? entries.get(name).bytes ?? bytesFor(name));
      return;
    }
    const [name, version] = parts;
    if (options.status) { response.statusCode = options.status; response.end('{}'); return; }
    if (options.redirect) { response.statusCode = 302; response.setHeader('Location', '/redirected'); response.end(); return; }
    if (version === 'latest') {
      const latest = options.latest?.get(name);
      if (latest === undefined) { response.statusCode = 404; response.end('{}'); return; }
      response.end(JSON.stringify({ name, version: latest }));
      return;
    }
    const entry = entries.get(name);
    if (!entry) { response.statusCode = 404; response.end('{}'); return; }
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ name, version, dist: {
      integrity: integrity(entry.bytes ?? bytesFor(name)),
      tarball: entry.tarball ?? `${mock.url}/archives/${name}.tgz`,
    }, ...entry.metadata }));
  });
  return { ...mock, requests };
}
function options(value, mock) {
  return { registryURL: `${mock.url}/` };
}

test('publication planning is read-only and orders native packages before the SDK', async () => {
  const value = stagedFixture();
  const mock = await registry();
  try {
    const plan = await createPlan(value.release, options(value, mock));
    assert.equal(plan.packages.length, 7);
    assert.equal(plan.packages.at(-1).name, pkg.name);
    assert.ok(plan.packages.every(item => item.action === 'publish'));
    assert.ok(mock.requests.every(request => request.method === 'GET'));
    assert.equal(plan.distTag, 'latest');
  } finally { await mock.close(); cleanup(value); }
});

test('a partial-release retry verifies existing archive bytes and uploads only missing packages', async () => {
  const value = stagedFixture();
  const existing = new Map([[`${pkg.name}-darwin-x64`, {}], [`${pkg.name}-darwin-arm64`, {}]]);
  const mock = await registry(existing);
  try {
    const plan = await createPlan(value.release, options(value, mock));
    assert.equal(plan.packages.filter(item => item.action === 'skip').length, 2);
    assert.equal(mock.requests.filter(request => request.path.startsWith('/archives/')).length, 2);
    const uploads = [];
    publishPlan(plan, { env: environment(), run: item => uploads.push(item.name) });
    assert.equal(uploads.length, 5);
    assert.equal(uploads.at(-1), pkg.name);
    assert.ok(uploads.every(name => !existing.has(name)));
  } finally { await mock.close(); cleanup(value); }
});

test('conflicting published bytes stop the entire plan before any upload', async () => {
  const value = stagedFixture();
  const mock = await registry(new Map([[pkg.name, { bytes: Buffer.from('different archive') }]]));
  try {
    await assert.rejects(createPlan(value.release, options(value, mock)), /Published bytes differ/);
    assert.equal(fs.readdirSync(value.archives).length, 8);
    assert.ok(mock.requests.every(request => request.method === 'GET'));
  } finally { await mock.close(); cleanup(value); }
});

test('matching registry metadata does not bypass published archive verification', async () => {
  const value = stagedFixture();
  const mock = await registry(new Map([[pkg.name, { download: Buffer.from('corrupted download') }]]));
  try {
    await assert.rejects(createPlan(value.release, options(value, mock)), /Published archive integrity mismatch/);
  } finally { await mock.close(); cleanup(value); }
});

test('registry errors are not mistaken for unpublished packages', async () => {
  const value = stagedFixture();
  try {
    for (const status of [401, 403, 429, 500]) {
      const mock = await registry(new Map(), { status });
      try { await assert.rejects(createPlan(value.release, options(value, mock)), /Registry (?:latest )?lookup failed/); }
      finally { await mock.close(); }
    }
  } finally { cleanup(value); }
});

test('publication checks reject redirected lookups and off-origin archive locations', async () => {
  const value = stagedFixture();
  const redirect = await registry(new Map(), { redirect: true });
  const foreign = await registry(new Map([[pkg.name, { tarball: 'https://example.invalid/secret-bearing-path.tgz' }]]));
  try {
    await assert.rejects(createPlan(value.release, options(value, redirect)));
    await assert.rejects(createPlan(value.release, options(value, foreign)), /same origin/);
  } finally { await redirect.close(); await foreign.close(); cleanup(value); }
});

test('a changed local archive invalidates a plan before the first upload', async () => {
  const value = stagedFixture();
  const mock = await registry();
  try {
    const plan = await createPlan(value.release, options(value, mock));
    fs.writeFileSync(plan.packages.at(-1).archive, 'changed after planning');
    const uploads = [];
    assert.throws(() => publishPlan(plan, { env: environment(), run: item => uploads.push(item.name) }), /Local archive changed/);
    assert.equal(uploads.length, 0);
  } finally { await mock.close(); cleanup(value); }
});

test('publication requires an upstream main or matching SDK tag push, hosted runner and OIDC', () => {
  const plan = { repository: 'mongodb/kingfisher', version: pkg.version };
  const main = { GITHUB_REF_TYPE: 'branch', GITHUB_REF_NAME: 'main', GITHUB_REF: 'refs/heads/main' };
  for (const source of [{}, main]) {
    checkPublishEnvironment(plan, environment(source));
    for (const change of [{ GITHUB_ACTIONS: 'false' }, { RUNNER_ENVIRONMENT: 'self-hosted' },
      { GITHUB_REPOSITORY: 'other/kingfisher' }, { GITHUB_EVENT_NAME: 'pull_request' },
      { GITHUB_EVENT_NAME: 'workflow_dispatch' }, { GITHUB_EVENT_NAME: '' },
      { GITHUB_REF_TYPE: 'branch', GITHUB_REF_NAME: 'development', GITHUB_REF: 'refs/heads/development' },
      { GITHUB_REF_NAME: 'v2.17.0' }, { GITHUB_REF: 'refs/heads/feature/main' },
      { ACTIONS_ID_TOKEN_REQUEST_URL: '' }, { ACTIONS_ID_TOKEN_REQUEST_TOKEN: '' }]) {
      assert.throws(() => checkPublishEnvironment(plan, environment({ ...source, ...change })));
    }
  }
  assert.throws(() => checkPublishEnvironment(plan, environment({ GITHUB_REF_TYPE: 'branch' })));
  assert.throws(() => checkPublishEnvironment(plan, environment({ ...main, GITHUB_REF_TYPE: 'tag' })));
});

test('sibling CLI and Python release tags match their own source manifest versions', () => {
  const plan = { repository: 'mongodb/kingfisher', version: pkg.version };
  for (const [prefix, relative] of [['v', 'Cargo.toml'], ['python-v', 'crates/kingfisher-python/Cargo.toml']]) {
    const text = fs.readFileSync(path.resolve(__dirname, '../..', relative), 'utf8');
    const version = /^version\s*=\s*"([^"]+)"/m.exec(text)[1];
    const tag = `${prefix}${version}`;
    checkPublishEnvironment(plan, environment({ GITHUB_REF_NAME: tag, GITHUB_REF: `refs/tags/${tag}` }));
    for (const invalid of [`${prefix}9999.9999.9999`, `${tag}-rc.1`, `${tag}+build`, `${prefix}01.2.3`]) {
      assert.throws(() => checkPublishEnvironment(plan, environment({
        GITHUB_REF_NAME: invalid, GITHUB_REF: `refs/tags/${invalid}` })), /source manifest/);
    }
  }
});

test('sibling tag validation cannot borrow a dependency version', context => {
  const original = fs.readFileSync;
  context.mock.method(fs, 'readFileSync', (file, ...args) => {
    if (file === path.resolve(__dirname, '../../Cargo.toml')) {
      return '[package]\nname = "kingfisher-bin"\n[dependencies.example]\nversion = "1.2.3"\n';
    }
    return original(file, ...args);
  });
  assert.throws(() => checkPublishEnvironment({ repository: 'mongodb/kingfisher', version: pkg.version },
    environment({ GITHUB_REF_NAME: 'v1.2.3', GITHUB_REF: 'refs/tags/v1.2.3' })), /stable package version/);
});

test('guarded manual publication requires main, explicit authorization and the exact pinned SHA', () => {
  const plan = { repository: 'mongodb/kingfisher', version: pkg.version };
  const manual = { GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF_TYPE: 'branch',
    GITHUB_REF_NAME: 'main', GITHUB_REF: 'refs/heads/main', GITHUB_SHA: 'a'.repeat(40),
    KINGFISHER_RELEASE_EXPECTED_SHA: 'a'.repeat(40), KINGFISHER_RELEASE_PUBLISH: 'true' };
  checkPublishEnvironment(plan, environment(manual));
  for (const change of [{ KINGFISHER_RELEASE_PUBLISH: '' }, { KINGFISHER_RELEASE_PUBLISH: 'false' },
    { KINGFISHER_RELEASE_EXPECTED_SHA: '' }, { KINGFISHER_RELEASE_EXPECTED_SHA: 'a'.repeat(7) },
    { KINGFISHER_RELEASE_EXPECTED_SHA: `${'a'.repeat(40)}\n`, GITHUB_SHA: `${'a'.repeat(40)}\n` },
    { KINGFISHER_RELEASE_EXPECTED_SHA: '0'.repeat(40), GITHUB_SHA: '0'.repeat(40) },
    { KINGFISHER_RELEASE_EXPECTED_SHA: 'b'.repeat(40) }, { GITHUB_SHA: 'b'.repeat(40) },
    { GITHUB_REF: `refs/tags/npm-v${pkg.version}`, GITHUB_REF_TYPE: 'tag', GITHUB_REF_NAME: `npm-v${pkg.version}` },
    { GITHUB_REF: 'refs/heads/development', GITHUB_REF_NAME: 'development' },
    { GITHUB_REPOSITORY: 'fork/kingfisher' }, { RUNNER_ENVIRONMENT: 'self-hosted' },
    { ACTIONS_ID_TOKEN_REQUEST_TOKEN: '' }]) {
    assert.throws(() => checkPublishEnvironment(plan, environment({ ...manual, ...change })));
  }
});

test('verified npm-tag handoff keeps the original trusted workflow and exact cohort SHA', context => {
  const plan = { repository: 'mongodb/kingfisher', version: pkg.version };
  const sha = 'a'.repeat(40);
  context.mock.method(childProcess, 'execFileSync', (command, args, options) => {
    assert.equal(command, 'git');
    assert.equal(options.cwd, path.resolve(__dirname, '../..'));
    assert.deepEqual(args, ['rev-parse', 'HEAD']);
    return `${sha}\n`;
  });
  const manual = { GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_SHA: sha,
    GITHUB_WORKFLOW_REF: `mongodb/kingfisher/.github/workflows/node-sdk.yml@refs/tags/npm-v${pkg.version}`,
    KINGFISHER_RELEASE_PUBLISH: 'true', KINGFISHER_RELEASE_COHORT: 'true',
    KINGFISHER_RELEASE_EXPECTED_SHA: sha };
  checkPublishEnvironment(plan, environment(manual));
  for (const change of [{ KINGFISHER_RELEASE_COHORT: '' }, { KINGFISHER_RELEASE_COHORT: 'false' },
    { KINGFISHER_RELEASE_PUBLISH: 'false' }, { KINGFISHER_RELEASE_EXPECTED_SHA: '' },
    { KINGFISHER_RELEASE_EXPECTED_SHA: 'b'.repeat(40) }, { GITHUB_SHA: 'b'.repeat(40) },
    { GITHUB_SHA: sha.slice(0, 7) }, { GITHUB_SHA: `${sha}\n` }, { GITHUB_SHA: '0'.repeat(40) },
    { GITHUB_WORKFLOW_REF: '' },
    { GITHUB_WORKFLOW_REF: `mongodb/kingfisher/.github/workflows/release.yml@refs/tags/npm-v${pkg.version}` },
    { GITHUB_WORKFLOW_REF: 'mongodb/kingfisher/.github/workflows/node-sdk.yml@refs/heads/main' },
    { GITHUB_REF_NAME: 'npm-v9.9.9', GITHUB_REF: 'refs/tags/npm-v9.9.9' },
    { RUNNER_ENVIRONMENT: 'self-hosted' }, { GITHUB_REPOSITORY: 'fork/kingfisher' },
    { ACTIONS_ID_TOKEN_REQUEST_TOKEN: '' }]) {
    assert.throws(() => checkPublishEnvironment(plan, environment({ ...manual, ...change })));
  }
});

test('coordinator manual CLI-tag completion pins the checkout and its committed stable version', context => {
  const plan = { repository: 'mongodb/kingfisher', version: pkg.version };
  const sha = 'a'.repeat(40);
  const calls = [];
  context.mock.method(childProcess, 'execFileSync', (command, args, options) => {
    assert.equal(command, 'git');
    assert.equal(options.cwd, path.resolve(__dirname, '../..'));
    calls.push(args);
    if (args.join(' ') === 'rev-parse HEAD') return `${sha}\n`;
    assert.deepEqual(args, ['show', `${sha}:Cargo.toml`]);
    return "[package] # committed package version, not the mutable worktree\nname = 'kingfisher-bin'\nversion = '2.14.0'\n";
  });
  const manual = { GITHUB_EVENT_NAME: 'workflow_dispatch', GITHUB_REF_TYPE: 'tag',
    GITHUB_REF_NAME: 'v2.14.0', GITHUB_REF: 'refs/tags/v2.14.0', GITHUB_SHA: sha,
    KINGFISHER_RELEASE_PUBLISH: 'true' };
  checkPublishEnvironment(plan, environment(manual));
  assert.deepEqual(calls, [['rev-parse', 'HEAD'], ['show', `${sha}:Cargo.toml`]]);
  for (const change of [{ KINGFISHER_RELEASE_PUBLISH: '' }, { KINGFISHER_RELEASE_PUBLISH: 'false' },
    { GITHUB_SHA: '' }, { GITHUB_SHA: sha.slice(0, 7) }, { GITHUB_SHA: `${sha}\n` },
    { GITHUB_SHA: '0'.repeat(40) }, { GITHUB_SHA: 'b'.repeat(40) },
    { GITHUB_REF_TYPE: 'branch' }, { GITHUB_REF_NAME: 'v9.9.9', GITHUB_REF: 'refs/tags/v9.9.9' },
    { GITHUB_REF_NAME: 'v2.14.0-rc.1', GITHUB_REF: 'refs/tags/v2.14.0-rc.1' },
    { GITHUB_REF_NAME: 'v2.14.0+build', GITHUB_REF: 'refs/tags/v2.14.0+build' },
    { GITHUB_REF_NAME: `npm-v${pkg.version}`, GITHUB_REF: `refs/tags/npm-v${pkg.version}` },
    { GITHUB_REF_NAME: 'python-v1.5.0', GITHUB_REF: 'refs/tags/python-v1.5.0' },
    { GITHUB_EVENT_NAME: 'pull_request' }, { GITHUB_EVENT_NAME: 'workflow_call' },
    { GITHUB_REPOSITORY: 'fork/kingfisher' }, { RUNNER_ENVIRONMENT: 'self-hosted' },
    { ACTIONS_ID_TOKEN_REQUEST_TOKEN: '' }]) {
    assert.throws(() => checkPublishEnvironment(plan, environment({ ...manual, ...change })));
  }
});

test('an authorized npm tag publication uploads the tested platform archives before the SDK', async () => {
  const value = stagedFixture();
  const mock = await registry();
  try {
    const plan = await createPlan(value.release, options(value, mock));
    const uploads = [];
    publishPlan(plan, { env: environment(), run: item => uploads.push(item.archive) });
    assert.deepEqual(uploads, readArchives(value.release).map(item => item.archive));
    assert.equal(plan.packages.at(-1).name, pkg.name);
  } finally { await mock.close(); cleanup(value); }
});

test('a failed publication stops later packages and never ignores upload errors', async () => {
  const value = stagedFixture();
  const mock = await registry();
  try {
    const plan = await createPlan(value.release, options(value, mock));
    const uploads = [];
    assert.throws(() => publishPlan(plan, { env: environment(), run: item => {
      uploads.push(item.name);
      if (uploads.length === 3) throw new Error('synthetic upload failure');
    } }), /synthetic upload failure/);
    assert.equal(uploads.length, 3);
    assert.ok(!uploads.includes(pkg.name));
  } finally { await mock.close(); cleanup(value); }
});

test('the npm pack adapter seals all genuine tarballs without executing lifecycle scripts', () => {
  const value = stagedFixture(packPackage);
  try {
    const archives = readArchives(value.release);
    assert.equal(archives.length, 7);
    for (const archive of archives) assert.ok(fs.statSync(archive.archive).size > 0);
  } finally { cleanup(value); }
});

test('release archives are packed once and every retry verifies rather than repacks them', () => {
  let calls = 0;
  const value = stagedFixture((...args) => { calls++; return pack(...args); });
  try {
    assert.equal(calls, 7);
    const original = readArchives(value.release);
    assert.deepEqual(packRelease(value.release, { pack: () => { throw new Error('must not repack'); } }), original);
    fs.appendFileSync(original[0].archive, 'corruption');
    assert.throws(() => readArchives(value.release), /Tested archive changed/);
    assert.throws(() => packRelease(value.release), /Tested archive changed/);
  } finally { cleanup(value); }
});

test('archive manifests reject incomplete matrices and unsafe filenames before publication', async () => {
  const value = stagedFixture();
  try {
    const file = path.join(value.archives, 'manifest.json');
    const original = fs.readFileSync(file);
    const manifest = JSON.parse(original);
    manifest.packages[0].filename = '../outside.tgz';
    fs.writeFileSync(file, JSON.stringify(manifest));
    await assert.rejects(createPlan(value.release, { fetch: () => { throw new Error('must not contact registry'); } }), /Unexpected archive path/);
    const incomplete = JSON.parse(original);
    incomplete.packages.pop();
    fs.writeFileSync(file, JSON.stringify(incomplete));
    assert.throws(() => readArchives(value.release), /Incomplete archive matrix/);
  } finally { cleanup(value); }
});

test('interrupted packing leaves no partial archives and preserves the staged release', () => {
  const value = fixture();
  try {
    success(run(value.root, 'collect-artifacts.cjs'));
    const release = path.join(value.root, 'release');
    let calls = 0;
    assert.throws(() => packRelease(release, { pack: (...args) => {
      if (++calls === 3) throw new Error('synthetic packing failure');
      return pack(...args);
    } }), /synthetic packing failure/);
    assert.ok(!fs.existsSync(path.join(release, 'archives')));
    assert.ok(!fs.readdirSync(release).some(name => name.startsWith('.archives-stage-')));
    assert.equal(checkRelease(release).length, 7);
  } finally { cleanup(value); }
});

test('stable maintenance releases never move a newer latest tag backward', async () => {
  const value = stagedFixture();
  const mock = await registry(new Map(), { latest: new Map([[`${pkg.name}-darwin-x64`, '9.0.0']]) });
  try {
    const plan = await createPlan(value.release, options(value, mock));
    assert.equal(plan.distTag, `backport-${pkg.version.split('.').slice(0, 2).join('.')}`);
    const tags = [];
    publishPlan(plan, { env: environment(), run: (_item, tag) => tags.push(tag) });
    assert.equal(tags.length, 7);
    assert.ok(tags.every(tag => tag === plan.distTag));
  } finally { await mock.close(); cleanup(value); }
});

test('registry latest semver permits valid prereleases and build metadata without rewinding newer cores', async () => {
  const value = stagedFixture();
  const latest = new Map();
  const mock = await registry(new Map(), { latest });
  try {
    for (const [version, tag] of [[pkg.version + '+build.01', 'latest'], ['0.0.0-alpha.1+build.01', 'latest'],
      ['9.0.0-rc.1+build.01', `backport-${pkg.version.split('.').slice(0, 2).join('.')}`]]) {
      latest.set(pkg.name, version);
      assert.equal((await createPlan(value.release, options(value, mock))).distTag, tag);
    }
  } finally { await mock.close(); cleanup(value); }
});

test('malformed registry latest versions fail closed before uploading anything', async () => {
  const value = stagedFixture();
  const latest = new Map();
  const mock = await registry(new Map(), { latest });
  try {
    for (const version of ['not-a-version', '1.0.0-01', '1.0.0-alpha..1', '1.0.0+build..meta', '1.0.0\n', '1.0.0\r\n', '1.0.0-' + 'a'.repeat(256), null]) {
      latest.set(pkg.name, version);
      await assert.rejects(createPlan(value.release, options(value, mock)), /Invalid registry latest version/);
    }
  } finally { await mock.close(); cleanup(value); }
});
