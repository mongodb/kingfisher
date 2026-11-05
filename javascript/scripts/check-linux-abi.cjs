'use strict';
// Ubuntu 22.04 is the conservative release baseline, NOT manylinux/glibc 2.28.
// Inspect imported symbol versions as well as NEEDED libraries: merely building
// on an old runner does not establish the ABI of a prebuilt native dependency.
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const floors = { GLIBC: '2.35', GLIBCXX: '3.4.29', CXXABI: '1.3.13' };
const allowed = new Set(['libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'librt.so.1',
  'libresolv.so.2', 'libgcc_s.so.1', 'libstdc++.so.6', 'ld-linux-x86-64.so.2', 'ld-linux-aarch64.so.1']);
function greater(left, right) {
  const a = left.split('.').map(Number), b = right.split('.').map(Number);
  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    if ((a[index] ?? 0) !== (b[index] ?? 0)) return (a[index] ?? 0) > (b[index] ?? 0);
  }
  return false;
}
function checkABI(symbols, dynamic) {
  const seen = new Set();
  for (const line of symbols.split('\n').filter(line => /\bUND\b/.test(line))) {
    for (const match of line.matchAll(/@(GLIBCXX|GLIBC|CXXABI)_([\w.]+)/g)) {
      const [, family, version] = match;
      assert.match(version, /^\d+(?:\.\d+)+$/, `Private or unknown ${family} ABI: ${version}`);
      assert.ok(!greater(version, floors[family]), `${family}_${version} exceeds supported floor ${floors[family]}`);
      seen.add(`${family}_${version}`);
    }
  }
  assert.ok([...seen].some(value => value.startsWith('GLIBC_')), 'No versioned GLIBC imports found; check the readelf input');
  const needed = [...dynamic.matchAll(/\(NEEDED\).*\[([^\]]+)\]/g)].map(match => match[1]);
  assert.ok(needed.includes('libc.so.6'), 'Expected a GNU/Linux libc dependency');
  for (const library of needed) assert.ok(allowed.has(library), `Unexpected shared runtime dependency: ${library}`);
  return { versions: [...seen].sort(), needed };
}
if (require.main === module) {
  assert.equal(process.platform, 'linux', 'Run the ELF symbol audit on a GNU/Linux release runner');
  assert.ok(process.argv[2], 'Provide the native .node artifact');
  const readelf = args => execFileSync('readelf', ['--wide', ...args, process.argv[2]], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  const result = checkABI(readelf(['--dyn-syms']), readelf(['--dynamic']));
  console.log(`GNU/Linux ABI verified: GLIBC<=${floors.GLIBC}, GLIBCXX<=${floors.GLIBCXX}, CXXABI<=${floors.CXXABI}; ${result.needed.join(', ')}`);
}
module.exports = { checkABI, floors };
