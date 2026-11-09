import path from 'node:path';

const OUTCOME_META = {
  verified_active: {
    label: 'Active',
    tone: 'danger',
    hint: 'The provider confirmed this credential is live.',
  },
  verified_inactive: {
    label: 'Inactive',
    tone: 'ok',
    hint: 'The provider rejected this credential.',
  },
  unavailable: {
    label: 'Unavailable',
    tone: 'muted',
    hint: 'The provider could not be reached or returned an unexpected response.',
  },
  skipped: {
    label: 'Skipped',
    tone: 'muted',
    hint: 'Validation was skipped for this finding.',
  },
  assumed: {
    label: 'Assumed',
    tone: 'warn',
    hint: 'The rule assumes this credential is valid without a live check.',
  },
  locally_derived: {
    label: 'Local only',
    tone: 'muted',
    hint: 'The outcome was derived locally, not verified with the provider.',
  },
  invalid_material: {
    label: 'Invalid',
    tone: 'muted',
    hint: 'The detected material is not a usable credential.',
  },
  not_attempted: {
    label: 'Not attempted',
    tone: 'muted',
    hint: 'No provider validation was attempted for this finding.',
  },
};

const OUTCOME_ORDER = {
  verified_active: 0,
  unavailable: 1,
  not_attempted: 2,
  assumed: 3,
  locally_derived: 4,
  skipped: 5,
  invalid_material: 6,
  verified_inactive: 7,
};

const CONFIDENCE_ORDER = { high: 0, medium: 1, low: 2 };

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (character) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
  })[character]);
}

function formatNumber(value) {
  return new Intl.NumberFormat('en-US').format(value);
}

function counted(value, noun) {
  return `${formatNumber(value)} ${noun}${value === 1 ? '' : 's'}`;
}

function formatDuration(milliseconds) {
  if (milliseconds < 1000) return `${milliseconds} ms`;
  const seconds = Math.round(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  if (minutes < 60) return `${minutes}m ${remainder}s`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}

function formatDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return 'unknown';
  return date.toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  });
}

function displayPath(filePath, root) {
  const relative = path.relative(root, filePath);
  if (relative && !relative.startsWith('..') && !path.isAbsolute(relative)) {
    return relative;
  }
  return filePath;
}

function outcomeMeta(outcome) {
  return OUTCOME_META[outcome] ?? {
    label: outcome,
    tone: 'muted',
    hint: '',
  };
}

function isVerified(outcome) {
  return outcome === 'verified_active' || outcome === 'verified_inactive';
}

function formatCommitDate(timestamp) {
  if (timestamp === null || timestamp === undefined) return '';
  const seconds = Number(timestamp);
  if (!Number.isFinite(seconds)) return '';
  return new Date(seconds * 1000).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

function renderSource(entry) {
  if (entry.source !== 'history' || !entry.commit) return '';
  const commit = entry.commit;
  const date = formatCommitDate(commit.timestamp);
  return `<div class="commit-line" title="${esc(commit.message ?? '')}">
    <span class="tag history">history</span>
    <code>${esc(commit.shortId ?? commit.id.slice(0, 10))}</code>
    ${commit.author ? `<span>· ${esc(commit.author)}</span>` : ''}
    ${date ? `<span>· ${esc(date)}</span>` : ''}
  </div>`;
}

function renderAction(entry, canRevoke, sessionRevokeEnabled, root) {
  const revocation = entry.revocation ?? { status: 'none' };
  const http = revocation.httpStatus ? `HTTP ${revocation.httpStatus}` : '';

  if (revocation.status === 'revoked') {
    return `<span class="pill ok">Revoked</span>${http ? `<div class="sub">${esc(http)}</div>` : ''}`;
  }
  if (revocation.status === 'unknown') {
    return `<span class="pill warn" title="The request may have been submitted. Verify with the provider before retrying.">Outcome unknown</span>`;
  }
  if (revocation.status === 'not_confirmed') {
    return `<span class="pill warn" title="The provider did not confirm revocation.">Not confirmed</span>${http ? `<div class="sub">${esc(http)}</div>` : ''}`;
  }
  if (revocation.status === 'failed') {
    return `<span class="pill danger" title="${esc(revocation.error ?? 'Revocation failed.')}">Failed</span>`;
  }
  if (revocation.status === 'revoking') {
    return `<span class="pill muted">Revoking…</span>`;
  }

  if (!canRevoke) {
    let reason;
    if (!sessionRevokeEnabled) {
      reason = 'Revocation is disabled for this session.';
    } else if (entry.revocationReason) {
      reason = entry.revocationReason;
    } else if (entry.outcome !== 'verified_active') {
      reason = 'Only a live, verified-active credential can be revoked.';
    } else if (!entry.revocationReady) {
      reason = 'The rule validated this credential but does not provide a confirmed revocation action.';
    } else {
      reason = 'This finding cannot be revoked.';
    }
    return `<button type="button" class="btn danger" disabled title="${esc(reason)}">Revoke</button>`;
  }

  return `<button type="button" class="btn danger btn-revoke"
    data-id="${esc(entry.id)}"
    data-rule-name="${esc(entry.finding.ruleName)}"
    data-rule-id="${esc(entry.finding.ruleId)}"
    data-path="${esc(displayPath(entry.path, root))}"
    data-line="${esc(entry.finding.location.line)}"
    data-outcome="${esc(outcomeMeta(entry.outcome).label)}"
    data-http="${esc(entry.httpStatus ?? '')}">Revoke</button>`;
}

function renderDetails(entry, root, redacted) {
  const finding = entry.finding;
  const captures = finding.captures && Object.keys(finding.captures).length
    ? JSON.stringify(finding.captures, null, 2)
    : null;
  const diagnostics = entry.inputDiagnostics?.length
    ? JSON.stringify(entry.inputDiagnostics, null, 2)
    : null;
  const revocation = entry.revocation ?? {};

  return `<tr class="details-row" id="details-${esc(entry.id)}" hidden>
    <td colspan="6">
      <div class="details">
        <div class="details-grid">
          <div><span class="key">Rule ID</span><code>${esc(finding.ruleId)}</code></div>
          <div class="wide"><span class="key">Secret</span><pre class="secret-full">${esc(finding.secret ?? '')}</pre></div>
          <div><span class="key">Fingerprint</span><code>${esc(finding.fingerprint)}</code></div>
          <div><span class="key">Confidence</span>${esc(finding.confidence)}</div>
          <div><span class="key">Entropy</span>${esc(finding.entropy.toFixed(3))}</div>
          <div><span class="key">Location</span><code>${esc(displayPath(entry.path, root))}:${esc(finding.location.line)}:${esc(finding.location.column)}</code></div>
          <div><span class="key">Byte offsets</span><code>${esc(finding.location.startOffset)}–${esc(finding.location.endOffset)}</code></div>
          <div><span class="key">Blob ID</span><code>${esc(finding.blobId)}</code></div>
          <div><span class="key">Base64</span>${finding.isBase64Encoded ? 'yes' : 'no'}</div>
          <div><span class="key">Source</span>${entry.source === 'history' ? 'Git history' : 'Working tree'}</div>
          ${entry.commit ? `<div><span class="key">Commit</span><code>${esc(entry.commit.id)}</code></div>` : ''}
          ${entry.commit?.author ? `<div><span class="key">Author</span>${esc(entry.commit.author)}${entry.commit.email ? ` &lt;${esc(entry.commit.email)}&gt;` : ''}</div>` : ''}
          ${entry.commit?.timestamp ? `<div><span class="key">Commit date</span>${esc(formatCommitDate(entry.commit.timestamp))}</div>` : ''}
          ${entry.repository ? `<div class="wide"><span class="key">Repository</span><code>${esc(entry.repository)}</code></div>` : ''}
          ${entry.commit?.message ? `<div class="wide"><span class="key">Commit message</span>${esc(entry.commit.message)}</div>` : ''}
          <div><span class="key">Validation</span>${esc(outcomeMeta(entry.outcome).label)}${entry.httpStatus ? ` · HTTP ${esc(entry.httpStatus)}` : ''}</div>
          <div><span class="key">Revocation ready</span>${entry.revocationReady ? 'yes' : 'no'}${entry.revocationReason ? ` · ${esc(entry.revocationReason)}` : ''}</div>
          ${entry.reason ? `<div class="wide"><span class="key">Validation reason</span>${esc(entry.reason)}</div>` : ''}
          ${revocation.error ? `<div class="wide"><span class="key">Revocation error</span>${esc(revocation.error)}</div>` : ''}
          ${revocation.at ? `<div class="wide"><span class="key">Revocation attempted</span>${esc(formatDate(revocation.at))}${revocation.httpStatus ? ` · HTTP ${esc(revocation.httpStatus)}` : ''}</div>` : ''}
        </div>
        ${captures ? `<details class="raw"><summary>Captures (${redacted ? 'redacted by the SDK' : 'raw; sensitive'})</summary><pre>${esc(captures)}</pre></details>` : ''}
        ${diagnostics ? `<details class="raw"><summary>Validation input diagnostics</summary><pre>${esc(diagnostics)}</pre></details>` : ''}
      </div>
    </td>
  </tr>`;
}

function renderRow(entry, meta, root) {
  const finding = entry.finding;
  const outcome = outcomeMeta(entry.outcome);
  const searchText = [
    entry.path,
    displayPath(entry.path, root),
    finding.ruleName,
    finding.ruleId,
    outcome.label,
  ].join(' ').toLowerCase();
  const canRevoke = meta.revokeEnabled && meta.validate && entry.outcome === 'verified_active'
    && Boolean(entry.revocationReady) && entry.revocation?.status === 'none';
  const validated = isVerified(entry.outcome);
  const secretText = String(finding.secret ?? '');
  const secretPreview = secretText.replace(/\s+/g, ' ').slice(0, 140);
  const secretTruncated = secretText.replace(/\s+/g, ' ').length > 140;

  return `<tr class="finding" data-id="${esc(entry.id)}" data-search="${esc(searchText)}"
    data-outcome="${esc(entry.outcome)}" data-revocable="${canRevoke ? '1' : '0'}"
    data-validated="${validated ? '1' : '0'}"
    data-status="${esc(entry.revocation?.status ?? 'none')}">
    <td class="confidence"><span class="conf ${esc(finding.confidence)}">${esc(finding.confidence)}</span></td>
    <td class="rule">
      <div class="rule-name" title="${esc(finding.ruleName)}">${esc(finding.ruleName)}</div>
      <div class="rule-foot">
        <code>${esc(finding.ruleId)}</code>
        <button type="button" class="link details-toggle" data-target="${esc(entry.id)}" aria-expanded="false">details</button>
      </div>
    </td>
    <td class="loc">
      <code class="file" title="${esc(entry.path)}">${esc(displayPath(entry.path, root))}</code>
      <span class="line">:${esc(finding.location.line)}</span>
      ${renderSource(entry)}
    </td>
    <td class="secret">
      <code class="secret-value" title="${esc(secretText)}">${esc(secretPreview)}${secretTruncated ? '…' : ''}</code>
      ${finding.isBase64Encoded ? '<span class="tag">base64</span>' : ''}
    </td>
    <td class="validation">
      <span class="pill ${esc(outcome.tone)}" title="${esc(outcome.hint)}">${esc(outcome.label)}</span>
      ${entry.httpStatus ? `<div class="sub">HTTP ${esc(entry.httpStatus)}</div>` : ''}
      ${entry.outcome === 'verified_active' && !entry.revocationReady && entry.revocation?.status === 'none' ? `<div class="sub" title="${esc(entry.revocationReason ?? 'The rule has no confirmed revocation action.')}">no revoke action</div>` : ''}
    </td>
    <td class="actions">${renderAction(entry, canRevoke, meta.revokeEnabled, root)}</td>
  </tr>
  ${renderDetails(entry, root, meta.redact)}`;
}

const STYLES = `
:root {
  color-scheme: light dark;
  --bg: #f3f5fa;
  --bg-glow: #e6ecff;
  --panel: #ffffff;
  --panel-2: #f8fafc;
  --text: #111827;
  --text-2: #4b5563;
  --muted: #6b7280;
  --line: #e5e7eb;
  --line-strong: #d1d5db;
  --accent: #2563eb;
  --accent-2: #1d4ed8;
  --danger: #dc2626;
  --danger-bg: #fef2f2;
  --ok: #15803d;
  --ok-bg: #f0fdf4;
  --warn: #b45309;
  --warn-bg: #fffbeb;
  --muted-bg: #f3f4f6;
  --shadow: 0 12px 32px rgba(15, 23, 42, 0.08);
  --radius: 14px;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #080b12;
    --bg-glow: #101a33;
    --panel: #0f1521;
    --panel-2: #121a29;
    --text: #e5e7eb;
    --text-2: #9ca3af;
    --muted: #8b93a5;
    --line: #1f2937;
    --line-strong: #2b3648;
    --accent: #60a5fa;
    --accent-2: #3b82f6;
    --danger: #f87171;
    --danger-bg: rgba(248, 113, 113, 0.12);
    --ok: #4ade80;
    --ok-bg: rgba(74, 222, 128, 0.1);
    --warn: #fbbf24;
    --warn-bg: rgba(251, 191, 36, 0.1);
    --muted-bg: #161e2d;
    --shadow: 0 16px 40px rgba(0, 0, 0, 0.35);
  }
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body {
  margin: 0;
  color: var(--text);
  font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background:
    radial-gradient(1000px 500px at 10% -10%, var(--bg-glow), transparent 60%),
    var(--bg);
  min-height: 100vh;
}
body.modal-open { overflow: hidden; }
a { color: var(--accent); }
code, pre { font-family: var(--mono); }
.page { max-width: 1280px; margin: 0 auto; padding: 32px 24px 72px; }
.hero {
  display: flex; justify-content: space-between; gap: 24px; align-items: flex-start;
  padding: 28px; border: 1px solid var(--line); border-radius: var(--radius);
  background: linear-gradient(140deg, var(--panel), var(--panel-2));
  box-shadow: var(--shadow);
}
.eyebrow { color: var(--accent); font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; font-size: 11px; }
h1 { margin: 6px 0 10px; font-size: 32px; line-height: 1.15; letter-spacing: -0.02em; }
.root { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; color: var(--text-2); }
.root code { color: var(--text); background: var(--muted-bg); padding: 3px 7px; border-radius: 6px; font-size: 12px; word-break: break-all; }
.root-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
.meta { margin-top: 10px; color: var(--muted); font-size: 13px; }
.hero-badges { display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; max-width: 360px; }
.badge-soft {
  border: 1px solid var(--line-strong); border-radius: 999px; padding: 5px 10px;
  color: var(--text-2); font-size: 11px; font-weight: 600; white-space: nowrap;
  background: var(--panel);
}
.badge-soft.on { color: var(--accent); border-color: color-mix(in srgb, var(--accent) 35%, transparent); }
.badge-soft.off { color: var(--warn); border-color: color-mix(in srgb, var(--warn) 35%, transparent); }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 12px; margin: 18px 0; }
.stat {
  border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px;
  background: var(--panel); box-shadow: 0 2px 8px rgba(15, 23, 42, 0.03);
}
.stat .value { font-size: 26px; font-weight: 750; letter-spacing: -0.02em; }
.stat .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.07em; margin-top: 2px; }
.stat-sub { color: var(--muted); font-size: 10px; margin-top: 3px; }
.stat.danger .value { color: var(--danger); }
.stat.ok .value { color: var(--ok); }
.stat.accent .value { color: var(--accent); }
.banner, .warnings {
  border: 1px solid var(--line-strong); border-radius: 12px; padding: 12px 14px;
  background: var(--panel); margin-bottom: 14px; color: var(--text-2);
}
.banner.warn { border-color: color-mix(in srgb, var(--warn) 45%, transparent); background: var(--warn-bg); color: var(--text); }
.banner.danger { border-color: color-mix(in srgb, var(--danger) 45%, transparent); background: var(--danger-bg); color: var(--text); }
.banner strong { color: var(--text); }
.warnings summary { cursor: pointer; font-weight: 600; color: var(--text); }
.warnings ul { margin: 10px 0 0; padding-left: 20px; max-height: 220px; overflow: auto; }
.toolbar {
  display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin: 18px 0 10px;
}
.toolbar input[type="search"] {
  flex: 1 1 280px; min-width: 220px; padding: 10px 12px; border-radius: 9px;
  border: 1px solid var(--line-strong); background: var(--panel); color: var(--text);
  font: inherit; outline: none;
}
.toolbar input[type="search"]:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 18%, transparent); }
.toolbar select {
  padding: 10px 12px; border-radius: 9px; border: 1px solid var(--line-strong);
  background: var(--panel); color: var(--text); font: inherit;
}
.check { display: flex; gap: 7px; align-items: center; color: var(--text-2); cursor: pointer; user-select: none; }
.check input { accent-color: var(--accent); }
.count { color: var(--muted); font-size: 12px; margin-left: auto; }
.table-wrap { border: 1px solid var(--line); border-radius: var(--radius); background: var(--panel); box-shadow: var(--shadow); overflow: auto; }
table { width: 100%; border-collapse: collapse; min-width: 900px; }
thead th {
  position: sticky; top: 0; z-index: 1; text-align: left; padding: 11px 14px;
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted);
  background: var(--panel-2); border-bottom: 1px solid var(--line-strong); white-space: nowrap;
}
tbody td { padding: 13px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr.finding:hover td { background: color-mix(in srgb, var(--accent) 4%, transparent); }
tbody tr:last-child td { border-bottom: 0; }
tr[hidden], .details-row[hidden] { display: none; }
.conf { font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.06em; padding: 3px 7px; border-radius: 5px; }
.conf.high { color: var(--danger); background: var(--danger-bg); }
.conf.medium { color: var(--warn); background: var(--warn-bg); }
.conf.low { color: var(--muted); background: var(--muted-bg); }
.rule-name { font-weight: 650; max-width: 420px; }
.rule-foot { display: flex; gap: 10px; align-items: baseline; margin-top: 4px; flex-wrap: wrap; }
.rule code { color: var(--muted); font-size: 11px; }
.link { border: 0; background: none; padding: 0; color: var(--accent); font: inherit; font-size: 11px; cursor: pointer; }
.link:hover { text-decoration: underline; }
.file { font-size: 12px; word-break: break-all; }
.line { color: var(--muted); font-family: var(--mono); font-size: 12px; }
.secret code { color: var(--text-2); font-size: 12px; letter-spacing: 0.01em; }
.secret-value { display: inline-block; max-width: 340px; overflow-wrap: anywhere; white-space: pre-wrap; }
.secret-full { margin: 4px 0 0; padding: 10px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; white-space: pre-wrap; overflow-wrap: anywhere; max-height: 260px; overflow: auto; font-size: 11px; }
.tag { margin-left: 6px; padding: 2px 5px; border-radius: 4px; background: var(--muted-bg); color: var(--muted); font-size: 10px; }
.tag.history { margin-left: 0; color: var(--accent); background: color-mix(in srgb, var(--accent) 12%, transparent); }
.commit-line { display: flex; flex-wrap: wrap; gap: 5px; align-items: baseline; margin-top: 5px; color: var(--muted); font-size: 10px; }
.commit-line code { color: var(--text-2); font-size: 10px; }
.pill { display: inline-flex; align-items: center; gap: 5px; padding: 4px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; white-space: nowrap; }
.pill.danger { color: var(--danger); background: var(--danger-bg); }
.pill.ok { color: var(--ok); background: var(--ok-bg); }
.pill.warn { color: var(--warn); background: var(--warn-bg); }
.pill.muted { color: var(--muted); background: var(--muted-bg); }
.sub { color: var(--muted); font-size: 11px; margin-top: 4px; }
.actions { width: 130px; }
.btn {
  border: 1px solid var(--line-strong); background: var(--panel); color: var(--text);
  border-radius: 8px; padding: 7px 12px; font: inherit; font-weight: 600; cursor: pointer;
  transition: transform 0.06s ease, background 0.12s ease, border-color 0.12s ease;
}
.btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.btn:active:not(:disabled) { transform: translateY(1px); }
.btn:disabled { opacity: 0.42; cursor: not-allowed; }
.btn.danger { color: var(--danger); border-color: color-mix(in srgb, var(--danger) 35%, transparent); background: var(--danger-bg); }
.btn.danger:hover:not(:disabled) { border-color: var(--danger); background: color-mix(in srgb, var(--danger) 18%, var(--panel)); }
.btn.primary { color: #fff; background: var(--accent-2); border-color: var(--accent-2); }
.btn.primary:hover:not(:disabled) { background: var(--accent); color: #fff; }
.details-row td { background: var(--panel-2); padding: 0; }
.details { padding: 16px 18px 18px; border-bottom: 1px solid var(--line); }
.details-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px 18px; }
.details-grid .wide { grid-column: 1 / -1; }
.details .key { display: block; color: var(--muted); font-size: 10px; text-transform: uppercase; letter-spacing: 0.07em; margin-bottom: 3px; }
.details code { font-size: 11px; word-break: break-all; }
.raw { margin-top: 12px; }
.raw summary { cursor: pointer; color: var(--text-2); font-size: 12px; font-weight: 600; }
.raw pre { margin: 8px 0 0; padding: 12px; background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: auto; font-size: 11px; }
.empty { padding: 40px; text-align: center; color: var(--muted); }
.footer { margin-top: 22px; color: var(--muted); font-size: 12px; line-height: 1.7; }
.footer code { color: var(--text-2); }
.modal-backdrop {
  position: fixed; inset: 0; background: rgba(3, 7, 18, 0.62); backdrop-filter: blur(3px);
  display: flex; align-items: center; justify-content: center; padding: 20px; z-index: 20;
}
.modal-backdrop[hidden] { display: none; }
.modal {
  width: min(520px, 100%); border: 1px solid var(--line-strong); border-radius: 16px;
  background: var(--panel); box-shadow: 0 30px 80px rgba(0, 0, 0, 0.45); padding: 24px;
}
.modal h2 { margin: 0 0 6px; font-size: 22px; letter-spacing: -0.01em; }
.modal p { color: var(--text-2); }
.modal dl { display: grid; grid-template-columns: 100px 1fr; gap: 8px 14px; margin: 16px 0; }
.modal dt { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; padding-top: 2px; }
.modal dd { margin: 0; word-break: break-word; }
.modal .danger-note {
  border: 1px solid color-mix(in srgb, var(--danger) 40%, transparent);
  background: var(--danger-bg); border-radius: 10px; padding: 12px 14px; color: var(--text);
  font-size: 13px;
}
.modal .confirm { display: flex; gap: 9px; align-items: flex-start; margin: 16px 0 20px; color: var(--text); }
.modal .confirm input { margin-top: 4px; accent-color: var(--danger); }
.modal-actions { display: flex; justify-content: flex-end; gap: 10px; }
.toast {
  position: fixed; right: 24px; bottom: 24px; z-index: 30; max-width: 380px;
  padding: 12px 16px; border-radius: 10px; border: 1px solid var(--line-strong);
  background: var(--panel); color: var(--text); box-shadow: var(--shadow);
  opacity: 0; transform: translateY(10px); pointer-events: none; transition: 0.18s ease;
}
.toast.show { opacity: 1; transform: translateY(0); }
.toast.danger { border-color: color-mix(in srgb, var(--danger) 50%, transparent); }
.toast.ok { border-color: color-mix(in srgb, var(--ok) 50%, transparent); }
.toast.warn { border-color: color-mix(in srgb, var(--warn) 50%, transparent); }
noscript { display: block; padding: 12px 14px; }
@media (max-width: 1040px) {
  .stats { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .details-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .hero { flex-direction: column; }
  .hero-badges { justify-content: flex-start; max-width: none; }
}
@media (max-width: 640px) {
  .page { padding: 18px 12px 48px; }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  h1 { font-size: 26px; }
  .details-grid { grid-template-columns: 1fr; }
}
`;

const CLIENT_JS = `
(function () {
  'use strict';
  var tokenMeta = document.querySelector('meta[name="kf-token"]');
  var token = tokenMeta ? tokenMeta.content : '';
  var rows = Array.prototype.slice.call(document.querySelectorAll('tr.finding'));
  var search = document.getElementById('search');
  var outcomeFilter = document.getElementById('outcome-filter');
  var revocableOnly = document.getElementById('revocable-only');
  var validatedOnly = document.getElementById('validated-only');
  var visibleCount = document.getElementById('visible-count');
  var emptyState = document.getElementById('empty-state');
  var modal = document.getElementById('revoke-modal');
  var confirmCheck = document.getElementById('confirm-check');
  var confirmButton = document.getElementById('confirm-revoke');
  var cancelButton = document.getElementById('cancel-revoke');
  var toastElement = document.getElementById('toast');
  var toastTimer = null;
  var pending = null;

  function outcomeMatches(row, value) {
    if (value === 'all') return true;
    if (value === 'other') {
      return ['verified_active', 'verified_inactive', 'unavailable', 'assumed', 'not_attempted'].indexOf(row.dataset.outcome) === -1;
    }
    return row.dataset.outcome === value;
  }

  function detailsFor(row) {
    return document.getElementById('details-' + row.dataset.id);
  }

  function applyFilters() {
    var query = search.value.trim().toLowerCase();
    var outcome = outcomeFilter.value;
    var onlyRevocable = revocableOnly.checked;
    var onlyValidated = validatedOnly.checked;
    var shown = 0;
    rows.forEach(function (row) {
      var matches = (!query || row.dataset.search.indexOf(query) !== -1) &&
        outcomeMatches(row, outcome) &&
        (!onlyRevocable || row.dataset.revocable === '1') &&
        (!onlyValidated || row.dataset.validated === '1');
      row.hidden = !matches;
      var details = detailsFor(row);
      if (details) details.hidden = true;
      var toggle = row.querySelector('.details-toggle');
      if (toggle) toggle.setAttribute('aria-expanded', 'false');
      if (matches) shown += 1;
    });
    visibleCount.textContent = shown + ' of ' + rows.length + (rows.length === 1 ? ' finding' : ' findings');
    emptyState.hidden = rows.length === 0 || shown !== 0;
  }

  search.addEventListener('input', applyFilters);
  outcomeFilter.addEventListener('change', applyFilters);
  revocableOnly.addEventListener('change', applyFilters);
  validatedOnly.addEventListener('change', applyFilters);

  Array.prototype.forEach.call(document.querySelectorAll('.details-toggle'), function (toggle) {
    toggle.addEventListener('click', function () {
      var row = document.querySelector('tr.finding[data-id="' + toggle.dataset.target + '"]');
      if (!row) return;
      var details = detailsFor(row);
      if (!details) return;
      details.hidden = !details.hidden;
      toggle.setAttribute('aria-expanded', details.hidden ? 'false' : 'true');
    });
  });

  function toast(message, tone) {
    toastElement.textContent = message;
    toastElement.className = 'toast show ' + (tone || '');
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(function () {
      toastElement.className = 'toast';
    }, 6000);
  }

  function updateRevocableCount() {
    var stat = document.getElementById('stat-revocable');
    if (!stat) return;
    var count = rows.filter(function (row) {
      return row.dataset.revocable === '1' && row.dataset.status === 'none';
    }).length;
    stat.textContent = String(count);
  }

  function updateRow(row, data) {
    row.dataset.status = data.status;
    row.dataset.revocable = '0';
    var cell = row.querySelector('.actions');
    if (!cell) return;
    cell.textContent = '';
    var pill = document.createElement('span');
    pill.className = 'pill ' + (data.status === 'revoked' ? 'ok' : ['unknown', 'not_confirmed'].includes(data.status) ? 'warn' : 'danger');
    pill.textContent = data.status === 'revoked' ? 'Revoked'
      : data.status === 'unknown' ? 'Outcome unknown'
      : data.status === 'not_confirmed' ? 'Not confirmed'
      : 'Failed';
    if (data.error) pill.title = data.error;
    else if (data.httpStatus) pill.title = 'HTTP ' + data.httpStatus;
    cell.appendChild(pill);
    updateRevocableCount();
  }

  function openModal(button) {
    var row = button.closest('tr.finding');
    if (!row) return;
    pending = { row: row, id: row.dataset.id, button: button, submitting: false };
    document.getElementById('modal-rule').textContent = button.dataset.ruleName || 'Unknown rule';
    document.getElementById('modal-file').textContent = (button.dataset.path || '') + ':' + (button.dataset.line || '?');
    document.getElementById('modal-outcome').textContent = (button.dataset.outcome || 'Active') +
      (button.dataset.http ? ' (HTTP ' + button.dataset.http + ')' : '');
    confirmCheck.checked = false;
    confirmButton.disabled = true;
    confirmButton.textContent = 'Revoke credential';
    modal.hidden = false;
    document.body.classList.add('modal-open');
    confirmCheck.focus();
  }

  function closeModal() {
    var restore = pending && (pending.button.disabled ? pending.row.querySelector('.details-toggle') : pending.button);
    modal.hidden = true;
    document.body.classList.remove('modal-open');
    pending = null;
    if (restore) restore.focus();
  }

  Array.prototype.forEach.call(document.querySelectorAll('.btn-revoke'), function (button) {
    button.addEventListener('click', function () {
      if (!token) {
        toast('Open the live report URL to revoke credentials.', 'warn');
        return;
      }
      openModal(button);
    });
  });

  confirmCheck.addEventListener('change', function () {
    confirmButton.disabled = !confirmCheck.checked || Boolean(pending && pending.submitting);
  });

  cancelButton.addEventListener('click', closeModal);
  modal.addEventListener('click', function (event) {
    if (event.target === modal) closeModal();
  });
  document.addEventListener('keydown', function (event) {
    if (modal.hidden) return;
    if (event.key === 'Escape') closeModal();
    if (event.key !== 'Tab') return;
    var controls = modal.querySelectorAll('input:not([disabled]), button:not([disabled])');
    var first = controls[0], last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  });

  confirmButton.addEventListener('click', function () {
    if (!pending || pending.submitting || !confirmCheck.checked) return;
    var request = pending;
    request.submitting = true;
    request.button.disabled = true;
    request.row.dataset.revocable = '0';
    request.row.dataset.status = 'revoking';
    updateRevocableCount();
    confirmButton.disabled = true;
    confirmButton.textContent = 'Revoking…';
    fetch('/api/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-kf-token': token },
      body: JSON.stringify({ id: request.id, confirm: true })
    }).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        if (!response.ok) throw new Error(data.error || ('Revocation request failed: ' + response.status));
        return data;
      });
    }).then(function (data) {
      updateRow(request.row, data);
      closeModal();
      if (data.status === 'revoked') {
        toast('Credential revoked' + (data.httpStatus ? ' (HTTP ' + data.httpStatus + ')' : '') + '.', 'ok');
      } else if (data.status === 'unknown') {
        toast('Revocation outcome is unknown. Verify with the provider before retrying.', 'warn');
      } else if (data.status === 'not_confirmed') {
        toast('The provider did not confirm revocation' + (data.httpStatus ? ' (HTTP ' + data.httpStatus + ')' : '') + '.', 'warn');
      } else {
        toast('Revocation failed' + (data.error ? ': ' + data.error : '.'), 'danger');
      }
    }).catch(function (error) {
      // A dropped response may follow a submitted mutation. Never offer a blind
      // retry; reload the live state and verify with the provider out of band.
      updateRow(request.row, { status: 'unknown', error: error.message });
      closeModal();
      toast('No confirmed response. Reload the report and verify with the provider before any retry.', 'warn');
    });
  });

  applyFilters();
})();
`;

// Every interpolated input is HTML-escaped; the client script is constant source,
// never JSON-concatenated findings. Static output must not carry live authority.
export function renderReport({ entries, meta, token = '', interactive = false }) {
  if (!interactive) token = '';
  const sorted = [...entries].sort((left, right) => {
    const outcome = (OUTCOME_ORDER[left.outcome] ?? 99) - (OUTCOME_ORDER[right.outcome] ?? 99);
    if (outcome !== 0) return outcome;
    const confidence = (CONFIDENCE_ORDER[left.finding.confidence] ?? 99)
      - (CONFIDENCE_ORDER[right.finding.confidence] ?? 99);
    if (confidence !== 0) return confidence;
    return left.path.localeCompare(right.path)
      || (left.finding.location.line - right.finding.location.line);
  });

  const active = entries.filter((entry) => entry.outcome === 'verified_active').length;
  const inactive = entries.filter((entry) => entry.outcome === 'verified_inactive').length;
  const verified = active + inactive;
  const unavailable = entries.filter((entry) => entry.outcome === 'unavailable').length;
  const assumed = entries.filter((entry) => entry.outcome === 'assumed').length;
  const notAttempted = entries.filter((entry) => entry.outcome === 'not_attempted').length;
  const other = entries.length - verified - unavailable - assumed - notAttempted;
  const redacted = Boolean(meta.redact);
  const revocable = interactive && meta.revokeEnabled
    ? entries.filter((entry) => entry.revocationReady && entry.revocation?.status === 'none').length
    : 0;
  const revoked = entries.filter((entry) => entry.revocation?.status === 'revoked').length;
  const canRevoke = interactive && meta.revokeEnabled;
  const warnings = meta.warnings ?? [];
  const warningCount = meta.warningCount ?? warnings.length;
  const warningPreview = warnings.slice(0, 200);
  const rows = sorted.map((entry) => renderRow(entry, { ...meta, revokeEnabled: canRevoke }, meta.root)).join('');
  const history = meta.gitHistory ?? {};
  const historyEnabled = Boolean(history.enabled);
  const historyLabel = historyEnabled ? 'all refs and reachable history' : null;
  const rawFindings = meta.rawFindings ?? entries.length;
  const findingLabel = rawFindings !== entries.length
    ? `${formatNumber(entries.length)} of ${counted(rawFindings, 'finding')}`
    : counted(entries.length, 'finding');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="kf-token" content="${esc(token)}">
<title>Kingfisher Workbench — ${esc(meta.root)}</title>
<style>${STYLES}</style>
</head>
<body>
<div class="page">
  <header class="hero">
    <div class="hero-main">
      <div class="eyebrow">Kingfisher SDK ${esc(meta.version)} · secret scan</div>
      <h1>Kingfisher Workbench</h1>
      <div class="root"><span class="root-label">Root</span><code>${esc(meta.root)}</code></div>
      <div class="meta">
        ${esc(formatDate(meta.startedAt))} · ${esc(formatDuration(meta.durationMs))} ·
        ${counted(meta.scannedWorkingTree ?? meta.scanned, 'file')}${historyEnabled ? ` + ${counted(meta.scannedGitHistory ?? 0, 'historical file version')}` : ''} ·
        ${findingLabel} · ${counted(meta.rulesCount, 'detection rule')}
      </div>
    </div>
    <div class="hero-badges">
      ${redacted ? '<span class="badge-soft">Secrets redacted</span>' : '<span class="badge-soft off">Raw secrets visible</span>'}
      <span class="badge-soft">Loopback only</span>
      ${historyEnabled ? `<span class="badge-soft on">History: ${esc(historyLabel)}</span>` : ''}
      <span class="badge-soft">Confidence ≥ ${esc(meta.confidence ?? 'low')}</span>
      <span class="badge-soft">${meta.dedup === false ? 'All occurrences' : 'Deduped'}</span>
      ${meta.extract === false ? '' : `<span class="badge-soft">Extracted content</span>`}
      <span class="badge-soft ${meta.validate ? 'on' : 'off'}">Validation ${meta.validate ? 'on' : 'off'}</span>
      <span class="badge-soft ${meta.revokeEnabled ? 'on' : 'off'}">Revocation ${meta.revokeEnabled ? 'on' : 'off'}</span>
    </div>
  </header>

  <section class="stats">
    <div class="stat"><div class="value">${formatNumber(meta.scanned)}</div><div class="label">Inputs scanned</div></div>
    <div class="stat"><div class="value">${formatNumber(entries.length)}</div><div class="label">Findings</div></div>
    <div class="stat ok"><div class="value">${formatNumber(verified)}</div><div class="label">Verified</div><div class="stat-sub">${formatNumber(active)} active · ${formatNumber(inactive)} inactive</div></div>
    <div class="stat"><div class="value">${formatNumber(unavailable)}</div><div class="label">Unavailable</div><div class="stat-sub">provider inconclusive</div></div>
    <div class="stat"><div class="value">${formatNumber(assumed)}</div><div class="label">Assumed</div><div class="stat-sub">rule assumes valid</div></div>
    <div class="stat"><div class="value">${formatNumber(notAttempted)}</div><div class="label">Not attempted</div><div class="stat-sub">validation not run</div></div>
    ${other ? `<div class="stat"><div class="value">${formatNumber(other)}</div><div class="label">Other</div><div class="stat-sub">local, skipped or invalid</div></div>` : ''}
    <div class="stat accent"><div class="value" id="stat-revocable">${formatNumber(revocable)}</div><div class="label">Revocable now</div></div>
  </section>

  ${!interactive ? `<div class="banner warn"><strong>Static snapshot.</strong> This file cannot revoke credentials.${meta.liveUrl ? ` Open <a href="${esc(meta.liveUrl)}">${esc(meta.liveUrl)}</a> for the live report with working buttons.` : ''}</div>` : ''}
  ${!redacted ? '<div class="banner danger"><strong>Raw secrets are visible.</strong> This report contains unredacted credentials. Keep it on this machine, do not share <code>report.html</code>, and use <code>--redact</code> to hide values.</div>' : ''}
  ${interactive && !meta.validate ? '<div class="banner warn"><strong>Validation was disabled.</strong> Findings are unverified and cannot be revoked from this report.</div>' : ''}
  ${interactive && meta.validate && !meta.revokeEnabled ? '<div class="banner warn"><strong>Revocation is disabled.</strong> Start with <code>--validate --enable-revoke</code> only when authorized.</div>' : ''}
  ${interactive && meta.revokeEnabled ? '<div class="banner"><strong>Revocation is armed.</strong> A revoke button sends the original credential to the provider and permanently invalidates it. Each action requires confirmation and cannot be undone.</div>' : ''}

  ${warningCount ? `<details class="warnings"><summary>${formatNumber(warningCount)} input warning${warningCount === 1 ? '' : 's'}</summary><ul>${warningPreview.map((warning) => `<li><code>${esc(warning.path)}</code> — ${esc(warning.reason)}</li>`).join('')}</ul>${warningCount > warningPreview.length ? `<div class="sub">Showing ${warningPreview.length} of ${formatNumber(warningCount)} warnings.</div>` : ''}</details>` : ''}

  <div class="toolbar">
    <input id="search" type="search" placeholder="Filter by file, rule, or outcome…" autocomplete="off">
    <select id="outcome-filter" aria-label="Filter by validation outcome">
      <option value="all">All outcomes</option>
      <option value="verified_active">Active</option>
      <option value="verified_inactive">Inactive</option>
      <option value="unavailable">Unavailable</option>
      <option value="assumed">Assumed</option>
      <option value="not_attempted">Not attempted</option>
      <option value="other">Other</option>
    </select>
    <label class="check" title="Show only provider-confirmed active or inactive findings"><input type="checkbox" id="validated-only"> Verified only</label>
    <label class="check"><input type="checkbox" id="revocable-only"> Revocable only</label>
    <span class="count" id="visible-count">${formatNumber(entries.length)} of ${counted(entries.length, 'finding')}</span>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Confidence</th>
          <th>Rule</th>
          <th>Location</th>
          <th>Secret</th>
          <th>Validation</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="findings">
        ${rows || '<tr><td colspan="6"><div class="empty">No secrets were detected in the scanned files.</div></td></tr>'}
      </tbody>
    </table>
  </div>
  <div class="empty" id="empty-state" hidden>No findings match the current filters.</div>

  <div class="footer">
    Generated by <code>kingfisher-secret-scanner ${esc(meta.version)}</code>.
    Secrets and captures are ${redacted ? 'redacted' : 'shown unredacted'} in this report. Verified-active results stay in the server process only;
    closing the server disables revocation from this page.${revoked ? ` ${formatNumber(revoked)} credential${revoked === 1 ? '' : 's'} revoked in this session.` : ''}
    ${historyEnabled ? `<br>Git history: ${esc(historyLabel)}; ${counted(meta.scannedGitHistory ?? 0, 'historical file version')} scanned.` : ''}
    <br>${counted(meta.skipped ?? 0, 'input')} skipped by Workbench exclusions.
    <br>Reporting: confidence ≥ ${esc(meta.confidence ?? 'low')}, ${counted(rawFindings, 'raw visible finding')} → ${formatNumber(entries.length)} reported (${meta.dedup === false ? 'all occurrences' : 'deduplicated by rule + secret'}); extraction ${meta.extract === false ? 'off' : `depth ${formatNumber(meta.extractionDepth ?? 0)}`}.
    <br>Validation can send credentials to third-party providers. Revocation is irreversible — verify out of band when an outcome is unknown.
  </div>
</div>

<div class="modal-backdrop" id="revoke-modal" hidden>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="revoke-title">
    <h2 id="revoke-title">Revoke this credential?</h2>
    <p>This sends a revocation request using the original, provider-verified credential.</p>
    <dl>
      <dt>Rule</dt><dd id="modal-rule">—</dd>
      <dt>File</dt><dd><code id="modal-file">—</code></dd>
      <dt>Validation</dt><dd id="modal-outcome">—</dd>
    </dl>
    <div class="danger-note"><strong>This is destructive and cannot be undone.</strong> The credential will stop working for every application that uses it.</div>
    <label class="confirm"><input type="checkbox" id="confirm-check"> I understand this permanently revokes the credential.</label>
    <div class="modal-actions">
      <button type="button" class="btn" id="cancel-revoke">Cancel</button>
      <button type="button" class="btn danger" id="confirm-revoke" disabled>Revoke credential</button>
    </div>
  </div>
</div>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<noscript><div class="banner warn">JavaScript is disabled. The findings are readable, but filtering and revocation require JavaScript.</div></noscript>
<script>${CLIENT_JS}</script>
</body>
</html>`;
}
