// Development-only dependency selection; npm users do not need this script.
// Spawn a fresh Node so CLI arguments, test discovery, and signal handling are
// identical to the installed-package path. No symlink or package install needed.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const sdk = fileURLToPath(new URL('../../../index.mjs', import.meta.url));
const [mode, ...args] = process.argv.slice(2);
const entry = { scan: 'src/main.mjs', demo: 'demo/run.mjs', test: '--test' }[mode];
if (!entry || !existsSync(sdk)) {
  throw new Error('Use checkout.mjs scan|demo|test from a Kingfisher source checkout with a built JavaScript addon.');
}
const child = spawn(process.execPath, [entry, ...args], {
  cwd: root, stdio: 'inherit', env: { ...process.env, KINGFISHER_WORKBENCH_SDK: sdk },
});
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => child.kill(signal));
child.on('error', (error) => { console.error(error.message); process.exitCode = 1; });
child.on('exit', (code, signal) => { process.exitCode = code ?? (signal === 'SIGINT' ? 130 : 1); });
