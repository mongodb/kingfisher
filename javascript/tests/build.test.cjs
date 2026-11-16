'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { createRequire } = require('node:module');
const { PassThrough } = require('node:stream');
const { test } = require('node:test');
const targets = require('../scripts/targets.cjs');
const pkg = require('../package.json');
const script = path.resolve(__dirname, '../scripts/build.cjs');
const source = fs.readFileSync(script, 'utf8');
const localRequire = createRequire(script);

function fixture(t, options = {}) {
  const prefix = 'kingfisher-node-build-';
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const root = path.join(temporary, 'checkout with spaces', 'javascript');
  fs.mkdirSync(root, { recursive: true });
  t.after(() => {
    assert.equal(path.dirname(temporary), path.resolve(os.tmpdir()));
    assert.ok(path.basename(temporary).startsWith(prefix));
    fs.rmSync(temporary, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const calls = [];
  let output = '';
  let diagnostics = '';
  let response = { code: 0, chunks: [] };
  let hostResponse = { status: 0, stdout: `rustc fixture\r\nhost: ${targets[0].target}\r\n` };
  const env = { ...options.env };
  const spawn = (command, args, configuration) => {
    calls.push({ command, args, configuration });
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    const current = response;
    queueMicrotask(() => {
      if (current.error) child.emit('error', current.error);
      for (const chunk of current.chunks ?? []) child.stdout.write(chunk);
      child.stdout.end();
      setImmediate(() => child.emit('close', current.code ?? null, current.signal ?? null));
    });
    return child;
  };
  const spawnSync = (command, args, configuration) => {
    assert.ok(command === 'rustc' || command === env.RUSTC, `Unexpected synchronous command: ${command}`);
    assert.deepEqual(Array.from(args), ['-vV']);
    calls.push({ command, args, configuration });
    return hostResponse;
  };
  const fakeRequire = id => id === 'node:child_process' ? { spawn, spawnSync } : localRequire(id);
  const module = { exports: {} };
  const process = {
    argv: ['node', script], env,
    execPath: 'mock-node', platform: options.platform ?? 'darwin', arch: options.arch ?? 'x64',
    stdout: { write(chunk) { output += chunk; } },
    stderr: { write(chunk) { diagnostics += chunk; } },
  };
  vm.runInNewContext(source, {
    require: fakeRequire, module, exports: module.exports, process,
    __dirname: path.join(root, 'scripts'), Buffer, console,
  }, { filename: script });
  assert.equal(typeof module.exports.build, 'function', 'The builder must be testable without launching Cargo');
  return {
    root, calls, env, process,
    build: args => module.exports.build(args),
    respond(value) { response = value; },
    host(value) { hostResponse = value; },
    artifact(target = targets[0], extra = {}) {
      const extension = target.os === 'win32' ? '.dll' : target.os === 'darwin' ? '.dylib' : '.so';
      // Deliberately unrelated to Cargo's default directory/profile layout.
      const library = path.join(temporary, 'custom output with spaces', target.suffix, `bridge${extension}`);
      fs.mkdirSync(path.dirname(library), { recursive: true });
      fs.writeFileSync(library, `native fixture ${target.suffix}`);
      return {
        reason: 'compiler-artifact',
        package_id: 'path+file:///mock-package#kingfisher-node@1.0.1',
        manifest_path: path.resolve(root, '../crates/kingfisher-node/Cargo.toml'),
        target: { name: pkg.napi.binaryName, kind: ['cdylib'], crate_types: ['cdylib'] },
        filenames: [library], fresh: false, ...extra,
      };
    },
    output: () => output,
    diagnostics: () => diagnostics,
  };
}

function jsonLines(...messages) { return messages.map(message => JSON.stringify(message)).join('\r\n'); }
function cargoCall(value) { return value.calls.find(call => call.command === (value.env.CARGO ?? 'cargo')); }
function assertLocked(call) {
  assert.ok(call.args.includes('--locked'));
  assert.ok(call.args.includes('--message-format=json-render-diagnostics'));
  assert.ok(call.args.includes('--lib'));
  assert.equal(call.args[call.args.indexOf('--package') + 1], 'kingfisher-node');
  assert.equal(call.configuration.shell, undefined, 'Never invoke Cargo through a shell');
  assert.equal(call.configuration.cwd.includes('checkout with spaces'), true);
}

test('production builds preserve node-release, locked Cargo and the Rust host target', async t => {
  const value = fixture(t);
  const artifact = value.artifact();
  value.respond({ code: 0, chunks: [jsonLines(artifact, { reason: 'build-finished', success: true })] });
  const destination = await value.build([]);
  const call = cargoCall(value);
  assertLocked(call);
  assert.equal(call.args[call.args.indexOf('--profile') + 1], 'node-release');
  assert.equal(call.args[call.args.indexOf('--target') + 1], targets[0].target);
  assert.equal(destination, path.join(value.root, `kingfisher_sdk.${targets[0].suffix}.node`));
  assert.deepEqual(fs.readFileSync(destination), fs.readFileSync(artifact.filenames[0]));
  assert.equal(fs.existsSync(path.join(value.root, '_native.cjs')), false, 'Do not generate a second private loader');
  assert.equal(fs.existsSync(path.join(value.root, '_native.d.ts')), false, 'Public declarations are maintained by hand');
});

test('debug builds use the Cargo dev default and leave tracked loader/declarations untouched', async t => {
  const value = fixture(t);
  for (const name of ['_native.cjs', '_native.d.ts']) fs.writeFileSync(path.join(value.root, name), `unchanged ${name}`);
  value.respond({ code: 0, chunks: [jsonLines(value.artifact())] });
  await value.build(['--debug']);
  assertLocked(cargoCall(value));
  assert.equal(cargoCall(value).args.includes('--profile'), false);
  assert.equal(cargoCall(value).args.includes('--debug'), false);
  for (const name of ['_native.cjs', '_native.d.ts']) assert.equal(fs.readFileSync(path.join(value.root, name), 'utf8'), `unchanged ${name}`);
});

for (const target of targets) {
  test(`explicit ${target.target} emits exactly ${target.suffix}, independent of the Node host`, async t => {
    const value = fixture(t, { platform: 'win32', arch: 'arm64' });
    const artifact = value.artifact(target);
    const ignored = value.artifact(target, {
      manifest_path: path.resolve(value.root, '../crates/unrelated/Cargo.toml'),
    });
    value.respond({ code: 0, chunks: [jsonLines(ignored, artifact)] });
    const destination = await value.build(['--target', target.target]);
    assert.equal(value.calls.length, 1, 'An explicit target needs no rustc host subprocess');
    assert.equal(path.basename(destination), `kingfisher_sdk.${target.suffix}.node`);
    assertLocked(cargoCall(value));
    assert.deepEqual(fs.readFileSync(destination), fs.readFileSync(artifact.filenames[0]));
    assert.deepEqual(fs.readdirSync(value.root), [path.basename(destination)]);
  });
}

test('target aliases and CARGO_BUILD_TARGET preserve target selection and Cargo overrides', async t => {
  const target = targets[5];
  for (const args of [[], ['-t', target.target], [`--target=${target.target}`]]) {
    const value = fixture(t, { env: {
      CARGO_BUILD_TARGET: target.target, CARGO: path.join('custom tools', 'cargo.exe'),
      CARGO_TARGET_DIR: path.join('custom tools', 'target'), RUSTFLAGS: '-C debuginfo=0',
      LIB: 'MSVC fixture', MACOSX_DEPLOYMENT_TARGET: '11.0',
    } });
    value.respond({ code: 0, chunks: [jsonLines(value.artifact(target, { fresh: true }))] });
    await value.build(args);
    const call = cargoCall(value);
    assertLocked(call);
    assert.equal(value.calls.length, 1);
    assert.equal(call.args[call.args.indexOf('--target') + 1], target.target);
    for (const [key, expected] of Object.entries(value.env)) assert.equal(call.configuration.env[key], expected);
    assert.equal(call.configuration.env.NAPI_TYPE_DEF_TMP_FOLDER, undefined);
  }
});

test('explicit target wins over the environment and Cargo flags remain argument arrays', async t => {
  const value = fixture(t, { env: { CARGO_BUILD_TARGET: targets[5].target } });
  value.respond({ code: 0, chunks: [jsonLines(value.artifact(targets[2]))] });
  const forwarded = ['--features', 'validation,git', '--no-default-features', '--target-dir', path.join('build output', 'target'), '--verbose'];
  await value.build(['--debug', '--target', targets[2].target, ...forwarded, '--', '--offline', '-j', '2']);
  const call = cargoCall(value);
  assertLocked(call);
  assert.equal(call.args[call.args.indexOf('--target') + 1], targets[2].target);
  for (const argument of [...forwarded, '--offline', '-j', '2']) assert.ok(call.args.includes(argument), `Missing forwarded ${argument}`);
  assert.equal(call.args.includes('--'), false, 'The napi passthrough separator is not a Cargo positional argument');
});

test('custom profile forwarding never guesses a profile artifact directory', async t => {
  const value = fixture(t);
  const artifact = value.artifact();
  value.respond({ code: 0, chunks: [jsonLines(artifact)] });
  await value.build(['--profile', 'custom-profile', '--all-features']);
  const call = cargoCall(value);
  assertLocked(call);
  assert.equal(call.args.filter(argument => argument === '--profile').length, 1);
  assert.equal(call.args[call.args.indexOf('--profile') + 1], 'custom-profile');
  assert.ok(call.args.includes('--all-features'));
});

test('Cargo JSON handles chunk boundaries, CRLF, final unterminated lines and rendered diagnostics', async t => {
  const value = fixture(t);
  const artifact = value.artifact();
  const diagnostic = 'warning: café fixture\n';
  const text = Buffer.from(`build output\r\n${jsonLines(
    { reason: 'compiler-message', message: { rendered: diagnostic } },
    { ...artifact, target: { ...artifact.target, crate_types: ['rlib'] } },
    { ...artifact, target: { ...artifact.target, name: 'other_crate' } },
    artifact,
  )}`);
  const chunks = Array.from(text, byte => Buffer.from([byte]));
  value.respond({ code: 0, chunks });
  const destination = await value.build(['--target', targets[0].target]);
  assert.ok(fs.existsSync(destination));
  assert.match(value.diagnostics(), /warning: café fixture/);
  assert.match(value.output(), /build output/);
});

test('only the cdylib is copied from Windows Cargo import/debug artifacts', async t => {
  const value = fixture(t);
  const artifact = value.artifact(targets[4]);
  artifact.filenames.unshift(`${artifact.filenames[0]}.lib`, `${artifact.filenames[0]}.pdb`, `${artifact.filenames[0]}.exp`);
  value.respond({ code: 0, chunks: [jsonLines(artifact, artifact)] });
  const destination = await value.build(['--target', targets[4].target]);
  assert.equal(fs.readFileSync(destination, 'utf8'), 'native fixture win32-x64-msvc');
});

test('failed or signalled Cargo cannot install a seemingly successful artifact', async t => {
  for (const result of [{ code: 101 }, { code: null, signal: 'SIGTERM' }]) {
    const value = fixture(t);
    const destination = path.join(value.root, `kingfisher_sdk.${targets[0].suffix}.node`);
    fs.writeFileSync(destination, 'previous build');
    value.respond({ ...result, chunks: [jsonLines(value.artifact())] });
    await assert.rejects(value.build(['--target', targets[0].target]), /cargo.*(101|SIGTERM)/i);
    assert.equal(fs.readFileSync(destination, 'utf8'), 'previous build');
  }
});

test('Cargo spawn errors and host-resolution failures are actionable and never copy outputs', async t => {
  const value = fixture(t);
  value.respond({ error: new Error('mock cargo unavailable') });
  await assert.rejects(value.build(['--target', targets[0].target]), /mock cargo unavailable/);
  assert.deepEqual(fs.readdirSync(value.root), []);
  for (const host of [
    { error: new Error('mock rustc unavailable') },
    { status: 1, stdout: 'host probe failed' },
    { status: 0, stdout: 'no host triple' },
  ]) {
    const other = fixture(t);
    other.host(host);
    await assert.rejects(other.build([]), /rustc|host/i);
    assert.equal(other.calls.filter(call => call.command === 'cargo').length, 0);
  }
});

test('missing, empty, ambiguous and wrong-kind artifacts fail closed', async t => {
  for (const mode of ['missing', 'empty', 'ambiguous', 'wrong-kind', 'wrong-platform']) {
    const value = fixture(t);
    const artifact = value.artifact();
    let artifacts = [artifact];
    if (mode === 'missing') artifacts = [];
    if (mode === 'empty') fs.writeFileSync(artifact.filenames[0], '');
    if (mode === 'ambiguous') {
      const duplicate = `${artifact.filenames[0]}.alternate.dylib`;
      fs.copyFileSync(artifact.filenames[0], duplicate);
      artifacts.push({ ...artifact, filenames: [duplicate] });
    }
    if (mode === 'wrong-kind') artifact.target.kind = ['bin'];
    if (mode === 'wrong-platform') artifact.filenames = [value.artifact(targets[4]).filenames[0]];
    value.respond({ code: 0, chunks: [jsonLines(...artifacts)] });
    await assert.rejects(value.build(['--target', targets[0].target]), /artifact|cdylib/i, mode);
    assert.equal(fs.readdirSync(value.root).some(name => name.endsWith('.node')), false, mode);
  }
});

test('invalid target arguments fail before launching Cargo', async t => {
  for (const args of [['--target'], ['-t'], ['--target='], ['--target', '--offline'], ['--target', 'x86_64-unknown-linux-musl']]) {
    const value = fixture(t);
    await assert.rejects(value.build(args), /target/i);
    assert.equal(value.calls.length, 0);
  }
});
