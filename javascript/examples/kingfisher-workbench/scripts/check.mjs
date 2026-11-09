// Syntax-check the example without loading a native addon or installing tools.
import { readdir } from 'node:fs/promises';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
for (const directory of ['src', 'demo', 'scripts', 'test']) {
  for (const file of await readdir(path.join(root, directory))) {
    if (!file.endsWith('.mjs')) continue;
    const result = spawnSync(process.execPath, ['--check', path.join(root, directory, file)], { stdio: 'inherit' });
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status ?? 1);
  }
}
console.log('All example modules passed node --check.');
