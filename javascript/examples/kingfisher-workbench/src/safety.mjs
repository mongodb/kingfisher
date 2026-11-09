// Shared report-only safety policy. Never use these plain objects as operational
// SDK state: redaction and serialization intentionally discard sensitive context.
import crypto from 'node:crypto';
import path from 'node:path';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { mkdir, open, rename, rm, lstat } from 'node:fs/promises';

// Node resolves module URLs through symlinks (including macOS /var → /private/var),
// while argv may retain the caller's spelling. Canonicalize BOTH paths. Avoid
// import.meta.main: the supported Node 22.13.0 floor does not provide it.
export function isCliEntrypoint(moduleUrl) {
  if (!process.argv[1]) return false;
  try { return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(moduleUrl)); }
  catch { return false; }
}

// Only fixed, application-authored input diagnostics may cross the redacted
// error boundary. Never trust an arbitrary provider error's message or flags.
const INPUT_MESSAGES = Object.freeze({
  INVALID_ROOT: 'Select an existing directory to scan',
  OUTPUT_COLLISION: 'Audit, HTML and JSON outputs must be different files',
  VALIDATION_REQUIRED: 'Revocation requires explicit --validate',
  NON_REGULAR_OUTPUT: 'Refusing to replace a non-regular report output',
  AUDIT_EXISTS: 'Audit path already exists; select a new --audit file',
});
export class WorkbenchInputError extends Error {
  constructor(kind, options) {
    if (!Object.hasOwn(INPUT_MESSAGES, kind)) throw new TypeError('Unknown Workbench input error');
    super(INPUT_MESSAGES[kind], options);
    this.name = 'WorkbenchInputError';
    this.code = `ERR_WORKBENCH_${kind}`;
  }
}

// Local filesystem failures on the user's own root/outputs. Report the code and
// syscall only: messages and error.path can still contain sensitive locations.
const FILESYSTEM_CODES = new Set([
  'EACCES', 'EPERM', 'EROFS', 'ENOSPC', 'EDQUOT', 'EEXIST', 'ENOENT', 'ENOTDIR', 'EISDIR',
  'ELOOP', 'ENAMETOOLONG', 'EMFILE', 'ENFILE', 'EBUSY', 'EXDEV',
]);
export function errorForReport(error, redact = true) {
  if (error instanceof WorkbenchInputError) return `${error.code}: ${INPUT_MESSAGES[error.code.slice('ERR_WORKBENCH_'.length)]}`;
  if (!redact) return String(error?.message ?? error);
  // Provider/transport messages can echo credentials, URLs and response bodies.
  if (/^ERR_[A-Z0-9_]+$/.test(error?.code)) return error.code;
  if (FILESYSTEM_CODES.has(error?.code)) {
    return /^[a-z]+$/.test(error.syscall) ? `${error.code} (${error.syscall})` : error.code;
  }
  return 'operation_failed';
}
export function findingKey(finding) {
  // Use only inside the process. Not a public fingerprint: hashing a low-entropy
  // secret still permits dictionary attacks, so strip this key from every export.
  return crypto.createHash('sha256').update(finding.ruleId).update('\0').update(finding.secret).digest('hex');
}
export function dedupeEntries(entries) {
  const best = new Map();
  for (const entry of entries) {
    const previous = best.get(entry.dedupeKey);
    if (!previous || (entry.outcome === 'verified_active' && previous.outcome !== 'verified_active')) best.set(entry.dedupeKey, entry);
  }
  return [...best.values()];
}

export async function writePrivateFile(destination, data) {
  // Reports may contain raw secrets when explicitly requested. A sibling private
  // file plus rename avoids following a pre-existing symlink and avoids readers
  // observing half-written HTML. POSIX mode is best effort on Windows; use ACLs.
  const target = path.resolve(destination);
  await mkdir(path.dirname(target), { recursive: true });
  const existing = await lstat(target).catch((error) => { if (error.code !== 'ENOENT') throw error; });
  if (existing && !existing.isFile()) throw new WorkbenchInputError('NON_REGULAR_OUTPUT');
  const temporary = path.join(path.dirname(target), `.kingfisher-workbench-${crypto.randomUUID()}.tmp`);
  const handle = await open(temporary, 'wx', 0o600);
  try {
    try { await handle.writeFile(data); }
    finally { await handle.close(); }
    // Both paths are absolute and the temporary path was created exclusively by
    // this invocation. Only the explicitly selected output is replaced.
    await rename(temporary, target);
  } finally {
    await rm(temporary, { force: true });
  }
}
