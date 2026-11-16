'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');
const { createInterface } = require('node:readline');
const targets = require('./targets.cjs');
const { napi: { binaryName } } = require('../package.json');
const root = path.resolve(__dirname, '..');

async function build(args = process.argv.slice(2)) {
  let debug = false;
  let triple;
  const forwarded = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    if (argument === '--debug') debug = true;
    else if (argument === '--target' || argument === '-t' || argument.startsWith('--target=')) {
      triple = argument.startsWith('--target=') ? argument.slice('--target='.length) : args[++index];
      if (!triple || triple.startsWith('-')) throw new Error('A Rust target triple is required after --target');
    } else if (argument !== '--') forwarded.push(argument);
  }
  triple ??= process.env.CARGO_BUILD_TARGET || undefined;
  if (!triple) {
    const host = spawnSync(process.env.RUSTC || 'rustc', ['-vV'], {
      cwd: root, env: process.env, encoding: 'utf8',
    });
    if (host.error) throw new Error('Cannot determine the Rust host target with rustc -vV', { cause: host.error });
    if (host.status !== 0) throw new Error(`rustc host target probe failed (exit ${host.status})`);
    triple = /^host:\s+(\S+)\s*$/m.exec(host.stdout)?.[1];
    if (!triple) throw new Error('rustc -vV did not report a host target');
  }
  const target = targets.find(target => target.target === triple);
  if (!target) throw new Error(`Unsupported native SDK target: ${triple}`);

  const customProfile = forwarded.some(argument => argument === '--profile' || argument.startsWith('--profile='));
  const cargoArgs = ['build', '--manifest-path', '../Cargo.toml', '--package', 'kingfisher-node', '--lib',
    ...(!debug && !customProfile ? ['--profile', 'node-release'] : []), ...forwarded,
    '--target', triple, '--message-format=json-render-diagnostics', '--locked'];
  const child = spawn(process.env.CARGO || 'cargo', cargoArgs, {
    cwd: root, env: process.env, stdio: ['inherit', 'pipe', 'inherit'],
  });
  const artifacts = new Set();
  const manifest = path.resolve(root, '../crates/kingfisher-node/Cargo.toml');
  const extension = target.os === 'win32' ? '.dll' : target.os === 'darwin' ? '.dylib' : '.so';
  // Stream Cargo's JSON rather than buffering a workspace build or guessing its
  // target directory. Cached artifacts and custom --profile/--target-dir work too.
  await new Promise((resolve, reject) => {
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    lines.on('line', line => {
      let message;
      try { message = JSON.parse(line); }
      catch { process.stdout.write(`${line}\n`); return; }
      if (message?.reason === 'compiler-message' && typeof message.message?.rendered === 'string') {
        process.stderr.write(message.message.rendered);
      }
      if (message?.reason !== 'compiler-artifact' || message.target?.name !== binaryName ||
          !message.target.kind?.includes('cdylib') || !message.target.crate_types?.includes('cdylib') ||
          typeof message.manifest_path !== 'string' || path.resolve(root, message.manifest_path) !== manifest) return;
      for (const filename of message.filenames ?? []) {
        if (typeof filename === 'string' && path.extname(filename).toLowerCase() === extension) {
          artifacts.add(path.resolve(root, filename));
        }
      }
    });
    child.once('error', reject);
    child.once('close', (status, signal) => {
      lines.close();
      if (status === 0) resolve();
      else reject(new Error(`Cargo build failed (${signal || `exit ${status}`})`));
    });
  });
  if (artifacts.size !== 1) throw new Error(`Expected exactly one kingfisher-node cdylib artifact; found ${artifacts.size}`);
  const [artifact] = artifacts;
  const stat = fs.statSync(artifact);
  if (!stat.isFile() || stat.size === 0) throw new Error(`Missing or empty native cdylib artifact: ${artifact}`);
  const destination = path.join(root, `${binaryName}.${target.suffix}.node`);
  fs.copyFileSync(artifact, destination);
  // The tracked private loader and handwritten public declarations need no
  // generation. Runtime calls still load the Rust Node-API addon in process.
  return destination;
}

if (require.main === module) {
  build().catch(error => { console.error(error); process.exitCode = 1; });
}
module.exports = { build };
