'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const loader = fs.readFileSync(path.join(__dirname, '../_native.cjs'), 'utf8');

function rustExports(source) {
  const names = [];
  // Only column-zero attributes describe module exports; indented attributes
  // belong to methods. Fail closed on unsupported declarations/options so a new
  // export style cannot silently bypass this source-level, no-native-build check.
  const attributes = /^#\[napi(?:\(([\s\S]*?)\))?\]\s*((?:#\[[^\n]*\]\s*)*)([^\n]+)/gm;
  for (const match of source.matchAll(attributes)) {
    const options = (match[1] ?? '').split(',').map(value => value.trim()).filter(Boolean);
    assert.ok(options.every(value => /^(object|catch_unwind|js_name\s*=\s*"\w+")$/.test(value)),
      `Unrecognized napi options: ${match[0]}`);
    const item = match[3];
    if (/^impl\b/.test(item)) continue;
    const declaration = /^pub (struct|enum|(?:async )?fn) (\w+)/.exec(item);
    assert.ok(declaration, `Unrecognized napi declaration: ${item}`);
    if (options.includes('object')) continue; // Type-only, not a JS runtime export.
    const jsName = options.find(value => value.startsWith('js_name'))?.match(/"(\w+)"/)[1];
    names.push(jsName ?? (declaration[1].endsWith('fn')
      ? declaration[2].replace(/_([a-z])/g, (_, letter) => letter.toUpperCase())
      : declaration[2]));
  }
  return names;
}

function loaderExports(source) {
  return [...source.matchAll(/^module\.exports\.(\w+) = nativeBinding\.(\w+)$/gm)].map(match => {
    assert.equal(match[1], match[2]);
    return match[1];
  });
}

test('custom loader exports stay in sync with Rust napi runtime exports', () => {
  const root = path.join(__dirname, '../../crates/kingfisher-node/src');
  const expected = fs.readdirSync(root, { recursive: true })
    .filter(name => name.endsWith('.rs'))
    .flatMap(name => rustExports(fs.readFileSync(path.join(root, name), 'utf8')));
  assert.ok(expected.length > 0);
  assert.deepEqual(loaderExports(loader).sort(), expected.sort());
});

test('export guard recognizes functions, classes, enums and explicit names, not methods or objects', () => {
  assert.deepEqual(rustExports(`
#[napi(object)]
pub struct Options {}
#[napi]
#[derive(Clone)]
pub struct NativeExample {}
#[napi]
impl NativeExample {
    #[napi]
    pub fn method(&self) {}
}
#[napi(catch_unwind)]
pub async fn added_function() {}
#[napi(
    catch_unwind,
    js_name = "renamed",
)]
pub fn other_name() {}
#[napi]
pub enum Mode {}
`), ['NativeExample', 'addedFunction', 'renamed', 'Mode']);
  assert.throws(() => rustExports('#[napi(namespace = "new")]\npub fn added() {}'));
  assert.throws(() => rustExports('#[napi(\nnamespace = "new",\n)]\npub fn added() {}'));
  assert.throws(() => rustExports('#[napi]\npub mod nested {}'));
});

function loadWithVersions(version, bindingVersion) {
  const binding = Object.fromEntries(loaderExports(loader).map(name => [name, {}]));
  const module = { exports: {} };
  vm.runInNewContext(loader, {
    require(id) {
      if (id === 'fs') return fs;
      if (id === './package.json') return { version };
      if (id === 'kingfisher-secret-scanner-darwin-arm64') return binding;
      if (id === 'kingfisher-secret-scanner-darwin-arm64/package.json') return { version: bindingVersion };
      throw new Error(`Not installed: ${id}`);
    },
    module,
    process: { platform: 'darwin', arch: 'arm64', env: { NAPI_RS_ENFORCE_VERSION_CHECK: '1' } },
  }, { filename: '_native.cjs' });
  return module.exports;
}

test('native package version enforcement follows manifest, including future version bumps', () => {
  const version = require('../package.json').version;
  assert.ok(loadWithVersions(version, version).NativeScanner);
  assert.ok(loadWithVersions('99.12.3', '99.12.3').NativeScanner);
  assert.throws(() => loadWithVersions('99.12.3', version), error => {
    const messages = [];
    for (let cause = error; cause; cause = cause.cause) messages.push(cause.message);
    assert.match(messages.join('\n'), /expected 99\.12\.3/);
    return true;
  });
  const comparisons = [...loader.matchAll(/bindingPackageVersion !== ([^\s)&]+)/g)];
  assert.ok(comparisons.length > 0);
  for (const match of comparisons) assert.equal(match[1].trim(), 'packageVersion');
  const diagnostics = [...loader.matchAll(/version mismatch, expected (.*?) but got/g)];
  assert.equal(diagnostics.length, comparisons.length);
  for (const match of diagnostics) assert.equal(match[1], '${packageVersion}');
});
