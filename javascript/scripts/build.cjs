'use strict';
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const args = process.argv.slice(2);
const debug = args[0] === '--debug';
if (debug) args.shift();
const cli = path.resolve(__dirname, '../node_modules/@napi-rs/cli/dist/cli.js');
const result = spawnSync(process.execPath, [cli, 'build', '--platform',
  ...(!debug ? ['--profile', 'node-release'] : []),
  '--manifest-path', '../Cargo.toml', '--package', 'kingfisher-node', '--output-dir', '.',
  '--js', '_native.cjs', '--dts', '_native.d.ts', ...args, '--', '--locked'], {
  cwd: path.resolve(__dirname, '..'), stdio: 'inherit',
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
