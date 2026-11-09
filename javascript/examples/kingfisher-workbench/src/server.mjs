// The live capability stays in memory: a random session token, a loopback-only
// listener, and callbacks to original native results. Disk snapshots are inert.
import { createServer } from 'node:http';
import { mkdir, open, stat } from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { renderReport } from './report.mjs';
import { errorForReport, WorkbenchInputError, writePrivateFile } from './safety.mjs';

function json(response, status, body) {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(payload),
    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
  });
  response.end(payload);
}
function tokensMatch(expected, received) {
  if (typeof received !== 'string') return false;
  const left = Buffer.from(expected), right = Buffer.from(received);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
async function readBody(request) {
  let size = 0;
  const chunks = [];
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 4096) throw new Error('Body exceeds 4096 bytes');
    chunks.push(chunk);
  }
  const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Expected an object');
  return body;
}

export async function startReportServer({ entries, meta, revokeEntry, outPath, auditPath, port = 0 }) {
  const token = crypto.randomBytes(32).toString('hex');
  const byId = new Map(entries.map((entry) => [entry.id, entry]));
  const pending = new Set();
  let hosts;
  let closing = false;
  // Render inside the queue, not when called: overlapping revocations must not let
  // an older render finish its rename after a newer one and leave stale state on disk.
  let snapshotWrites = Promise.resolve();
  const writeSnapshot = () => {
    const write = snapshotWrites.then(() => writePrivateFile(outPath, renderReport({ entries, meta, interactive: false })));
    snapshotWrites = write.catch(() => {});
    return write;
  };
  // Establish ownership before listening. Exclusive creation refuses regular
  // files, hardlinks and symlinks alike, without appending to or chmod'ing them.
  // Keep this descriptor for the whole session, not a path reopened per action.
  auditPath = meta.revokeEnabled && meta.validate
    ? path.resolve(auditPath ?? path.join(path.dirname(outPath), `revocations-${crypto.randomUUID()}.jsonl`))
    : null;
  if (auditPath === path.resolve(outPath)) throw new WorkbenchInputError('OUTPUT_COLLISION');
  if (auditPath) await mkdir(path.dirname(auditPath), { recursive: true });
  const auditHandle = auditPath ? await open(auditPath, 'ax', 0o600).catch((error) => {
    if (error.code === 'EEXIST') throw new WorkbenchInputError('AUDIT_EXISTS', { cause: error });
    throw error;
  }) : null;
  if (auditHandle) {
    try {
      // Resolve filesystem aliases too (directory links and case-insensitive
      // names), before a snapshot could replace this newly owned audit file.
      const output = await stat(outPath, { bigint: true }).catch((error) => { if (error.code !== 'ENOENT') throw error; });
      const owned = output && await auditHandle.stat({ bigint: true });
      if (output && output.dev === owned.dev && output.ino === owned.ino) throw new WorkbenchInputError('OUTPUT_COLLISION');
    } catch (error) { await auditHandle.close(); throw error; }
  }
  let auditWrites = Promise.resolve();
  async function audit(entry, details) {
    if (!auditHandle) return;
    const record = `${JSON.stringify({
      at: new Date().toISOString(), ruleId: entry.finding.ruleId, path: entry.path,
      line: entry.finding.location.line, fingerprint: entry.finding.fingerprint, ...details,
    })}\n`;
    // Concurrent actions still produce complete, ordered JSONL records.
    const write = auditWrites.then(() => auditHandle.writeFile(record));
    auditWrites = write.catch(() => {});
    await write;
  }
  async function revoke(entry) {
    // Shutdown can begin while a slow request body is being read. Check again
    // at the synchronous claim boundary, not only before awaiting the body.
    if (closing) return { status: 503, body: { error: 'Server is closing.' } };
    if (!meta.revokeEnabled || !meta.validate) return { status: 403, body: { error: 'Revocation is disabled. Explicit --validate --enable-revoke is required.' } };
    if (!entry.revocationReady || entry.outcome !== 'verified_active' || entry.revocation?.status !== 'none') {
      return { status: 409, body: { error: 'No unspent, verified-active native validation snapshot. Rescan before another attempt.' } };
    }
    // Claim synchronously before the first await: double-clicks/concurrent API
    // calls cannot submit the same native result twice, even on timeout.
    entry.revocationReady = false;
    entry.revocation = { status: 'revoking', at: new Date().toISOString() };
    try { await audit(entry, { status: 'attempt_started' }); }
    catch {
      entry.revocation = { status: 'failed', error: 'audit_unavailable', at: new Date().toISOString() };
      return { status: 500, body: { error: 'Audit unavailable; no provider request was sent. Rescan before retrying.' } };
    }
    let result;
    try { result = await revokeEntry(entry); }
    catch (error) {
      result = { status: error.outcomeUnknown ? 'unknown' : 'failed', code: error.code, outcomeUnknown: error.outcomeUnknown, error: errorForReport(error, meta.redact) };
    }
    const unknown = Boolean(result.outcomeUnknown || result.status === 'unknown');
    const status = unknown ? 'unknown' : result.status ?? (result.ok ? 'revoked' : 'failed');
    entry.revocation = {
      status, at: new Date().toISOString(), httpStatus: result.httpStatus ?? null,
      code: result.code ?? null, outcomeUnknown: unknown,
      error: result.error ? errorForReport({ message: result.error, code: result.code }, meta.redact) : null,
    };
    let persistenceError = false;
    try { await audit(entry, { status, httpStatus: entry.revocation.httpStatus, code: entry.revocation.code, outcomeUnknown: unknown }); }
    catch { persistenceError = true; }
    try { await writeSnapshot(); } catch { persistenceError = true; }
    // A persistence failure after submission is NOT a provider failure/retry
    // permission. Preserve the actual outcome and the spent capability.
    return { status: 200, body: { ok: status === 'revoked', id: entry.id, ...entry.revocation, persistenceError } };
  }
  async function handle(request, response) {
    const host = request.headers.host;
    if (!hosts?.has(host)) return json(response, 421, { error: 'Unexpected Host header.' });
    // Parse only origin-form request targets, never an attacker-supplied origin.
    if (!request.url?.startsWith('/') || request.url.startsWith('//')) return json(response, 400, { error: 'Invalid request target.' });
    const url = new URL(request.url, `http://${host}`);
    if (request.method === 'GET' && ['/', '/index.html'].includes(url.pathname)) {
      const html = renderReport({ entries, meta, token, interactive: true });
      response.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8', 'Content-Length': Buffer.byteLength(html),
        'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      });
      response.end(html);
      return;
    }
    if (request.method === 'GET' && url.pathname === '/api/health') return json(response, 200, { ok: true });
    if (request.method === 'GET' && url.pathname === '/favicon.ico') { response.writeHead(204); response.end(); return; }
    if (request.method !== 'POST' || url.pathname !== '/api/revoke') return json(response, 404, { error: 'Not found.' });
    if (closing) return json(response, 503, { error: 'Server is closing.' });
    if ((request.headers.origin && request.headers.origin !== `http://${host}`)
      || request.headers['sec-fetch-site'] === 'cross-site') return json(response, 403, { error: 'Cross-origin mutation is forbidden.' });
    if (!tokensMatch(token, request.headers['x-kf-token'])) return json(response, 403, { error: 'Invalid session token.' });
    if (request.headers['content-type']?.split(';')[0].trim().toLowerCase() !== 'application/json') return json(response, 415, { error: 'Use application/json.' });
    let body;
    try { body = await readBody(request); } catch { return json(response, 400, { error: 'Expected a JSON object of at most 4096 bytes.' }); }
    if (typeof body.id !== 'string' || body.confirm !== true) return json(response, 400, { error: 'An id and explicit confirm:true are required.' });
    const entry = byId.get(body.id);
    if (!entry) return json(response, 404, { error: 'Unknown finding id.' });
    const result = await revoke(entry);
    return json(response, result.status, result.body);
  }
  const server = createServer((request, response) => {
    const task = handle(request, response).catch(() => {
      if (!response.headersSent && !response.destroyed) json(response, 500, { error: 'Internal server error.' });
      else response.destroy();
    });
    pending.add(task);
    // Observe both outcomes. An ignored finally() result would itself reject if
    // even the error-response path failed (for example on a broken response).
    const settled = () => pending.delete(task);
    void task.then(settled, settled);
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', resolve);
    });
  } catch (error) {
    await auditHandle?.close();
    throw error;
  }
  const actualPort = server.address().port;
  hosts = new Set([`127.0.0.1:${actualPort}`, `localhost:${actualPort}`]);
  const url = `http://127.0.0.1:${actualPort}`;
  meta.liveUrl = url;
  return {
    url, port: actualPort, auditPath, writeSnapshot,
    async close() {
      closing = true;
      const stopped = new Promise((resolve) => server.close(resolve));
      try {
        // Wait for submitted provider mutations before releasing their native owner.
        await Promise.allSettled([...pending]);
        server.closeAllConnections();
        await stopped;
      } finally {
        await snapshotWrites;
        await auditWrites;
        await auditHandle?.close();
      }
    },
  };
}
