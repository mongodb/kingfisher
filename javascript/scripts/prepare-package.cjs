'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../..');
const destination = path.resolve(__dirname, '..');
const pkg = require('../package.json');
const nativeManifest = fs.readFileSync(path.join(root, 'crates/kingfisher-node/Cargo.toml'), 'utf8');
const nativeVersion = /^version\s*=\s*"([^"]+)"/m.exec(nativeManifest)?.[1];
if (nativeVersion !== pkg.version) throw new Error('JavaScript and native SDK versions must match');

for (const name of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES']) fs.copyFileSync(path.join(root, name), path.join(destination, name));
fs.copyFileSync(path.join(root, 'crates/kingfisher-rules/LICENSE'), path.join(destination, 'LICENSE-RULES'));
for (const [name, output] of Object.entries({ NOTICE: 'NOTICE-VECTORSCAN', 'LICENSE-VECTORSCAN': 'LICENSE-VECTORSCAN',
  'LICENSE-APACHE': 'LICENSE-VECTORSCAN-APACHE', 'LICENSE-MIT': 'LICENSE-VECTORSCAN-MIT' })) {
  fs.copyFileSync(path.join(root, 'third-party/kingfisher-vectorscan', name), path.join(destination, output));
}
