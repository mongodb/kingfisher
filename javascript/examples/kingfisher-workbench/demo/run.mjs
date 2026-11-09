// Safe end-to-end showcase: two invented credentials, a local mock, and a
// private disposable Git repository. Built-in rules are deliberately disabled,
// so opting into this demo's validation cannot contact a real provider.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { isCliEntrypoint } from '../src/safety.mjs';
import { parseArgs } from '../src/args.mjs';
import { runReport } from '../src/main.mjs';
import { startMockProvider } from './mock-provider.mjs';
import { createFixture } from './fixture.mjs';

export async function startDemo({ open = false, port = 0, onReady = () => {} } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-'));
  const controller = new AbortController();
  let mock;
  let running;
  try {
    mock = await startMockProvider(); // Await listening: no startup race.
    const fixture = await createFixture(directory, mock.url);
    const options = parseArgs([
      fixture.repository, '--rules', fixture.rules, '--no-builtins',
      '--validate', '--enable-revoke', '--allow-internal-ips',
      '--out', path.join(directory, 'report.html'), '--port', String(port),
      ...(open ? ['--open'] : []),
    ]);
    let ready, failed;
    const readiness = new Promise((resolve, reject) => { ready = resolve; failed = reject; });
    running = runReport(options, {
      signal: controller.signal,
      onReady(report) { onReady(report); ready(report); },
    });
    void running.catch(failed);
    const report = await readiness;
    console.log('[demo] Synthetic only. Current token is active; the historical token is retired.');
    console.log('[demo] Expand a finding, then Revoke → check confirmation → Revoke credential.');
    console.log('[demo] Ctrl+C removes only this private temporary fixture/report.');
    let closing;
    return {
      ...report, directory, fixture, mock, done: running,
      close() {
        closing ??= (async () => {
          controller.abort();
          try { await running; }
          finally {
            await mock.close();
            // directory is the exact absolute path returned by mkdtemp above,
            // never a caller-supplied worktree. Native/file handles are closed.
            await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
          }
        })();
        return closing;
      },
    };
  } catch (error) {
    controller.abort();
    await running?.catch(() => {});
    await mock?.close();
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
    throw error;
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.some((arg) => arg !== '--open')) throw new Error('Demo accepts only --open; normal scans use npm start.');
  let demo;
  let stopping = false;
  const stop = async () => {
    stopping = true;
    await demo?.close();
  };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  try {
    demo = await startDemo({ open: args.includes('--open') });
    if (stopping) await demo.close();
    await demo.done;
  } finally {
    await demo?.close();
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
  }
}
if (isCliEntrypoint(import.meta.url)) {
  try { await main(); } catch (error) { console.error(`[demo] ${error.message}`); process.exitCode = 1; }
}
