'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const targets = require('./targets.cjs');
const file = path.resolve(__dirname, '../package.json');
const original = fs.readFileSync(file);
// napi regenerates generic READMEs; keep our architecture/runtime prerequisites.
const readmes = targets.map(target => {
  const file = path.resolve(__dirname, '../npm', target.suffix, 'README.md');
  return { file, contents: fs.readFileSync(file) };
});
try {
  const cli = path.resolve(__dirname, '../node_modules/@napi-rs/cli/dist/cli.js');
  const result = spawnSync(process.execPath, [cli, 'create-npm-dirs'], { cwd: path.dirname(file), stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Platform package generation failed');
} finally {
  // Local file dependencies make npm ci work before target names exist on npm.
  // Release staging replaces these with exact registry versions, never source paths.
  fs.writeFileSync(file, original);
  for (const readme of readmes) fs.writeFileSync(readme.file, readme.contents);
}
for (const target of targets) {
  const file = path.resolve(__dirname, '../npm', target.suffix, 'package.json');
  const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
  manifest.private = true; // Only registry staging removes the development publishing guards.
  manifest.files = [...new Set([...manifest.files, 'README.md'])];
  fs.writeFileSync(file, JSON.stringify(manifest, null, 2) + '\n');
}
