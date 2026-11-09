import path from 'node:path';
import crypto from 'node:crypto';
import { stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { version } from './sdk.mjs';
import { HELP, parseArgs } from './args.mjs';
import { createAgent } from './agent.mjs';
import { createProgress } from './progress.mjs';
import { renderReport } from './report.mjs';
import { startReportServer } from './server.mjs';
import { dedupeEntries, errorForReport, isCliEntrypoint, WorkbenchInputError, writePrivateFile } from './safety.mjs';

function openBrowser(url) {
  // The URL is generated internally from a bound loopback port, not user text.
  // Windows start is a cmd builtin; never interpolate a scanned path into it.
  const command = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'cmd.exe' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/d', '/s', '/c', 'start', '""', url] : [url];
  const child = spawn(command, args, { stdio: 'ignore', detached: true });
  child.on('error', () => console.error('[report] Browser could not be opened; use the printed URL.'));
  child.unref();
}
function stopped(signal) {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => signal.addEventListener('abort', resolve, { once: true }));
}

// Also imported by the synthetic demo/tests. No process.exit() here: callers can
// close their own mock services only AFTER native work and submitted mutations
// have drained. A failed stage throws instead of exporting a partial success.
export async function runReport(options, { signal = new AbortController().signal, onReady = () => {} } = {}) {
  const root = options.root && await stat(options.root).catch((error) => {
    if (['ENOENT', 'ENOTDIR'].includes(error.code)) throw new WorkbenchInputError('INVALID_ROOT', { cause: error });
    throw error;
  });
  if (!root || !root.isDirectory()) throw new WorkbenchInputError('INVALID_ROOT');
  if (options.out === options.json) throw new WorkbenchInputError('OUTPUT_COLLISION');
  if (options.revoke && !options.validate) throw new WorkbenchInputError('VALIDATION_REQUIRED');
  // Select the exact excluded path before scanning; only a mutation-enabled live
  // server creates it. Every default session gets its own new private audit file.
  const auditPath = options.serve && options.revoke
    ? options.audit ?? path.join(path.dirname(options.out), `revocations-${crypto.randomUUID()}.jsonl`)
    : null;
  if (auditPath && [options.out, options.json].includes(auditPath)) throw new WorkbenchInputError('OUTPUT_COLLISION');
  options = { ...options, audit: auditPath };
  const progress = createProgress({ quiet: options.quiet, enabled: options.progress });
  const agents = [];
  const startedAt = new Date();
  let server;
  let ticker;
  try {
    const hasGit = Boolean(await stat(path.join(options.root, '.git')).catch(() => null));
    const history = options.gitHistory && hasGit;
    progress.banner('Kingfisher secret scan', [
      ['root', options.root], ['sources', history ? 'working tree + Git history (all refs)' : 'working tree'],
      ['validation', options.validate ? 'EXPLICITLY enabled; provider traffic permitted' : 'off · offline detection'],
      ['revocation', options.revoke ? 'armed · individual confirmation still required' : 'off'],
      ['secrets', options.redact ? 'redacted' : 'RAW · output is sensitive'],
    ]);
    if (options.validate) progress.log('[!] Validation sends credentials to providers defined by trusted rules.');
    ticker = setInterval(() => {
      const total = (key) => agents.reduce((sum, agent) => sum + agent.counters[key], 0);
      progress.update({
        phase: agents.at(-1)?.counters.phase ?? 'starting', inputs: total('inputs'), bytes: total('bytes'),
        findings: total('findings'), validated: total('validatedFindings'), reportable: total('findings'),
      });
    }, 200);
    ticker.unref();
    // Two in-process source agents keep live native snapshots independently.
    // No CLI subprocess, timestamp sharding, or serialized credential transport.
    for (const target of history ? ['tree', 'history'] : ['tree']) {
      signal.throwIfAborted();
      const agent = await createAgent({ options, target, signal });
      agents.push(agent);
      await agent.run();
    }
    clearInterval(ticker);
    signal.throwIfAborted();
    const ownerById = new Map(agents.flatMap((agent) => agent.entries.map((entry) => [entry.id, agent])));
    let entries = agents.flatMap((agent) => agent.entries);
    if (options.dedup) entries = dedupeEntries(entries);
    // This private credential digest is useful for comparison, unsafe as an
    // exported "fingerprint". Native SDK fingerprints remain lossless strings.
    for (const entry of agents.flatMap((agent) => agent.entries)) delete entry.dedupeKey;
    const finishedAt = new Date();
    const meta = {
      root: options.root, startedAt, finishedAt, durationMs: finishedAt - startedAt,
      scanned: agents.reduce((sum, agent) => sum + agent.counters.inputs, 0),
      scannedWorkingTree: agents[0].counters.inputs, scannedGitHistory: agents[1]?.counters.inputs ?? 0,
      gitHistory: { enabled: history },
      skipped: agents.reduce((sum, agent) => sum + agent.counters.skipped, 0),
      warnings: agents.flatMap((agent) => agent.warnings).slice(0, 200),
      warningCount: agents.reduce((sum, agent) => sum + agent.counters.warnings, 0),
      rawFindings: agents.reduce((sum, agent) => sum + agent.counters.findings, 0), reportedFindings: entries.length,
      confidence: options.confidence, redact: options.redact, dedup: options.dedup,
      extract: options.extract, extractionDepth: options.extractionDepth,
      validate: options.validate, revokeEnabled: options.revoke, timeoutMs: options.timeoutMs,
      rulesCount: agents[0].rulesCount, version, liveUrl: null,
    };
    if (options.json) await writePrivateFile(options.json, `${JSON.stringify({ meta, entries }, null, 2)}\n`);
    if (!options.serve) {
      await writePrivateFile(options.out, renderReport({ entries, meta }));
      console.log(`[report] snapshot: ${options.out}`);
      return { entries, meta };
    }
    server = await startReportServer({
      entries, meta, outPath: options.out, auditPath, port: options.port,
      revokeEntry: (entry) => ownerById.get(entry.id).revoke(entry.id),
    });
    await server.writeSnapshot();
    progress.stop();
    // Always print the URL, including --quiet, for automation and accessibility.
    console.log(`[report] live: ${server.url}`);
    console.log(`[report] snapshot: ${options.out}`);
    if (server.auditPath) console.log(`[report] audit: ${server.auditPath} (new private session file)`);
    if (options.json) console.log(`[report] json: ${options.json} (scan-time export; HTML is updated after revocation)`);
    console.log('[report] Ctrl+C closes the server and native resources.');
    onReady({ url: server.url, auditPath: server.auditPath, entries, meta });
    if (options.open) openBrowser(server.url);
    await stopped(signal);
    return { entries, meta };
  } finally {
    clearInterval(ticker);
    progress.stop();
    // Mutations already submitted must finish BEFORE native owners close.
    try { await server?.close(); }
    finally { await Promise.allSettled(agents.map((agent) => agent.close())); }
  }
}

async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); }
  catch (error) { console.error(error.message); process.exitCode = 2; return; }
  if (options.help) { console.log(HELP); return; }
  if (!options.root) { console.error(HELP); process.exitCode = 2; return; }
  const controller = new AbortController();
  const interrupt = () => controller.abort();
  process.once('SIGINT', interrupt);
  process.once('SIGTERM', interrupt);
  try { await runReport(options, { signal: controller.signal }); }
  catch (error) {
    if (controller.signal.aborted) process.exitCode = 130;
    else { console.error(`[fatal] ${errorForReport(error, options.redact)}`); process.exitCode = 1; }
  } finally {
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', interrupt);
  }
}
if (isCliEntrypoint(import.meta.url)) await main();
