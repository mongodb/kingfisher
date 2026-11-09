// One source's complete SDK lifecycle. Enumeration and transforms are explicit;
// detection is offline; validation and revocation are separate opt-in stages.
import crypto from 'node:crypto';
import path from 'node:path';
import { stat } from 'node:fs/promises';
import { DetectionScanner, Revoker, Rules, Validator, expandArchives, expandContent, filesystem, gitInputs } from './sdk.mjs';
import { errorForReport, findingKey } from './safety.mjs';

const CONFIDENCE_RANK = { low: 0, medium: 1, high: 2 };
export function passesConfidence(finding, minimum) {
  return (CONFIDENCE_RANK[finding.confidence] ?? 0) >= CONFIDENCE_RANK[minimum];
}
function check(signal) { signal?.throwIfAborted(); }

// Stop acquiring on the first failure, drain all already-submitted work, and
// preserve the original exception (including its SDK code/cause). A failed scan
// must never become a successful empty or partial report.
export async function pump(iterator, limit, handler, signal) {
  const pending = new Set();
  let failure;
  try {
    for await (const item of iterator) {
      check(signal);
      if (failure) throw failure;
      while (pending.size >= limit) {
        await Promise.race(pending);
        if (failure) throw failure;
        check(signal);
      }
      let task;
      task = Promise.resolve().then(() => handler(item)).catch((error) => { failure ??= error; }).finally(() => pending.delete(task));
      pending.add(task);
    }
  } finally {
    await Promise.all(pending);
  }
  if (failure) throw failure;
  check(signal);
}

function gitMetadata(input, redact) {
  if (!input.commit) return null;
  const origin = input.origins.find((item) => item.id === input.commit) ?? input.origins[0];
  return {
    id: input.commit, shortId: input.commit.slice(0, 10),
    timestamp: origin?.committer.timestamp ?? null,
    // Free-form commit metadata can contain credentials too. The default report
    // exports IDs and time only; raw metadata follows the explicit raw-data flag.
    author: redact ? null : origin?.author.name ?? null,
    email: redact ? null : origin?.author.email ?? null,
    message: redact ? null : origin?.message ?? null,
  };
}
function excluded(input, options, target) {
  // Filesystem inputs have absolute paths; history inputs are already relative.
  // Ancestors of the selected root must not participate in exclusion matching.
  const logicalPath = target === 'tree' ? path.relative(options.root, input.file ?? input.path) : input.path;
  const normalized = logicalPath.replaceAll('\\', '/');
  if (/(^|\/)(\.git|node_modules)(\/|$)/.test(normalized)) return true;
  if (options.exclude.some((text) => normalized.includes(text.replaceAll('\\', '/')))) return true;
  // Do not scan a previous report/audit while regenerating it in the input tree.
  if (target === 'tree') {
    const full = path.resolve(input.file ?? input.path);
    if ([options.out, options.json, options.audit].includes(full)) return true;
  }
  return false;
}

export async function createAgent({ options, target = 'tree', signal }) {
  const counters = { inputs: 0, bytes: 0, findings: 0, validatedFindings: 0, skipped: 0, warnings: 0, phase: 'starting' };
  const warnings = [];
  const warn = (warning) => { counters.warnings++; if (warnings.length < 200) warnings.push(warning); };
  const groups = [];
  const entries = [];
  const retained = new Map(); // opaque ID -> ORIGINAL native ValidationResult
  let scanner, validator, revoker;
  let closed = false;
  async function close() {
    if (closed) return;
    closed = true;
    retained.clear();
    groups.length = 0;
    await Promise.allSettled([scanner?.close(), validator?.close(), revoker?.close()]);
  }
  try {
    // Compile the requested confidence roots plus their declared dependencies,
    // not unrelated low-confidence detectors (including generic-api-key).
    const rules = await Rules.load({ paths: options.rules ? [options.rules] : [], builtins: options.builtins, confidence: options.confidence, includeDependencies: true, signal });
    scanner = await DetectionScanner.create({ rules, maxInputBytes: options.maxFileSize, maxPendingOperations: options.jobs });
    if (options.validate) validator = new Validator({
      concurrency: options.concurrency, retries: 0, timeoutMs: options.timeoutMs,
      allowInternalIps: options.allowInternalIps, httpFallbacks: false,
      maxPendingOperations: options.concurrency,
    });
    if (options.revoke) revoker = await Revoker.create({ rules: scanner.rules, timeoutMs: options.timeoutMs });
    check(signal);
  } catch (error) {
    await close();
    throw error;
  }

  function source() {
    if (target === 'history') return gitInputs(options.root, {
      mode: 'history', refs: null, discover: false,
      maxBlobSize: options.maxFileSize,
      maxCommits: options.gitHistoryMaxCommits || null,
      maxInputs: options.gitHistoryMaxInputs || null,
      skipMissingBlobs: true, signal, onWarning: warn,
    });
    return filesystem([options.root], {
      hidden: options.hidden, gitignore: options.gitignore,
      maxFileSize: options.maxFileSize, signal, onWarning: warn,
    });
  }
  async function* selectedSources() {
    for await (const input of source()) {
      check(signal);
      if (excluded(input, options, target)) { counters.skipped++; continue; }
      yield input; // Keep original ScanInput, raw filename bytes and provenance.
    }
  }
  function transformedSources() {
    const inputs = selectedSources();
    if (!options.extract) return inputs;
    // Adapters recognize their own formats and pass other sources through. They
    // retain repository/object IDs, raw paths and extraction context. Recoverable
    // extraction diagnostics arrive on ScanInput; thrown controls are NOT caught
    // and downgraded to raw bytes here.
    return expandContent(expandArchives(inputs, {
      depth: options.extractionDepth, maxBytes: options.maxExtractedSize, maxEntries: 10_000, signal,
    }), { sqlite: true, pyc: true, pdf: true, strict: false, maxBytes: options.maxExtractedSize, signal });
  }
  async function scanInput(input) {
    if (input.extractionError) warn({ path: input.path, reason: options.redact ? 'content_extraction_failed' : input.extractionError });
    const result = await scanner.scanInput(input, { signal });
    counters.inputs++;
    // byteLength reads the private snapshot's size; input.data would copy it.
    counters.bytes += input.byteLength ?? (await stat(input.file ?? input.path).catch(() => ({ size: 0 }))).size;
    const selected = result.findings.filter((finding) => finding.visible && passesConfidence(finding, options.confidence));
    counters.findings += selected.length;
    if (selected.length) groups.push({ input: result.input, findings: result.findings, selected });
  }
  function entryFor(finding, group, validation) {
    const serialized = validation?.toObject({ redact: options.redact });
    const ready = Boolean(options.revoke && validation?.outcome === 'verified_active' && validation.revocationReady);
    const id = crypto.randomUUID();
    if (ready) retained.set(id, validation);
    return {
      id, dedupeKey: findingKey(finding), path: group.input.path,
      source: target === 'history' ? 'history' : 'working-tree',
      repository: group.input.repository ?? null, commit: gitMetadata(group.input, options.redact),
      // This SDK projection includes origin IDs / extraction provenance, never
      // bytes. Raw filename bytes are encoded losslessly rather than guessed.
      input: { ...group.input.toJSON(), extractionError: options.redact && group.input.extractionError ? 'content_extraction_failed' : group.input.extractionError }, rawPathBase64: group.input.rawPath ? Buffer.from(group.input.rawPath).toString('base64') : null,
      finding: finding.toObject({ redact: options.redact }),
      outcome: validation?.outcome ?? 'not_attempted', httpStatus: validation?.httpStatus ?? null,
      reason: options.redact ? null : serialized?.reason ?? null,
      inputDiagnostics: options.redact ? [] : serialized?.inputDiagnostics ?? [],
      revocationSupported: validation?.revocationSupported ?? false, revocationReady: ready,
      revocationReason: options.redact ? null : validation?.revocationReason ?? null,
      revocation: { status: 'none', at: null, httpStatus: null, error: null },
    };
  }

  return {
    counters, entries, warnings, rulesCount: scanner.rules.length,
    async run() {
      counters.phase = 'scanning';
      await pump(transformedSources(), options.jobs, scanInput, signal);
      counters.phase = validator ? 'validating' : 'reporting';
      // Keep the WHOLE original input group for component association, while
      // authorizing provider work only for the visible, threshold-selected subset.
      // Supporting findings are context, never extra validation candidates.
      // Report deduplication happens only after validation across all contexts.
      async function* allGroups() { yield* groups; }
      await pump(allGroups(), options.concurrency, async (group) => {
        const results = validator ? await validator.validate(group.findings, { candidates: group.selected, signal, timeoutMs: options.timeoutMs }) : [];
        const key = (finding) => `${findingKey(finding)}:${finding.location.startOffset}`;
        const byFinding = new Map(results.map((result) => [key(result.finding), result]));
        for (const finding of group.selected) {
          entries.push(entryFor(finding, group, byFinding.get(key(finding))));
          if (validator) counters.validatedFindings++;
        }
      }, signal);
      groups.length = 0;
      counters.phase = 'done';
      return { entries, counters, warnings };
    },
    // Caller authorization is separate from SDK authorization. Only the server
    // checks session/confirmation; this map is the native ownership boundary.
    async revoke(id) {
      const original = retained.get(id);
      if (!revoker || !original) throw new Error('No retained native validation result for this finding');
      retained.delete(id); // one shot, including uncertain network outcomes
      try {
        const result = await revoker.revoke(original, { confirm: true, timeoutMs: options.timeoutMs });
        return { ok: result.revoked, status: result.revoked ? 'revoked' : 'not_confirmed', httpStatus: result.httpStatus, error: null };
      } catch (error) {
        return {
          ok: false, status: error.outcomeUnknown ? 'unknown' : 'failed',
          httpStatus: null, error: errorForReport(error, options.redact),
          code: error.code ?? null, outcomeUnknown: Boolean(error.outcomeUnknown),
        };
      }
    },
    close,
  };
}
