const state = {
  findings: [],
  accessMap: [],
};

const fileInput = document.getElementById('file');
const uploadBtn = document.getElementById('upload-btn');
const sampleBtn = document.getElementById('sample-btn');
const stats = {
  findings: document.getElementById('stat-findings'),
  access: document.getElementById('stat-access'),
  providers: document.getElementById('stat-providers'),
};
const findingsTable = document.getElementById('findings');
const accessTable = document.getElementById('access-map');
const payloadPreview = document.getElementById('payload-preview');

uploadBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files?.[0]) {
    loadFile(fileInput.files[0]);
  }
});

sampleBtn.addEventListener('click', async () => {
  const resp = await fetch('sample-report.json');
  const data = await resp.json();
  render(normalizePayload(data));
});

async function loadFile(file) {
  const text = await file.text();
  render(parseReport(text));
}

function parseReport(text) {
  try {
    const parsed = JSON.parse(text);
    return normalizePayload(parsed);
  } catch (_) {
    return parseJsonl(text);
  }
}

function parseJsonl(text) {
  const lines = text.split(/\r?\n/).filter(Boolean);
  const findings = [];
  let accessMap = [];
  lines.forEach((line) => {
    try {
      const row = JSON.parse(line);
      if (row.rule && row.finding) {
        findings.push(row);
      }
      if (row.access_map) {
        accessMap = accessMap.concat(row.access_map);
      }
    } catch (_) {
      /* ignore */
    }
  });
  return { findings, access_map: accessMap };
}

function normalizePayload(data) {
  if (Array.isArray(data)) {
    return { findings: data, access_map: [] };
  }
  return {
    findings: data.findings || [],
    access_map: normalizeAccessMap(data.access_map || []),
  };
}

function render(payload) {
  state.findings = payload.findings || [];
  state.accessMap = normalizeAccessMap(payload.access_map || []);

  const flattened = flattenAccessMap(state.accessMap);

  stats.findings.textContent = state.findings.length;
  stats.access.textContent = flattened.length;
  stats.providers.textContent = new Set(state.accessMap.map((e) => e.provider || '')).size;

  renderFindings();
  renderAccessMap(flattened);
  payloadPreview.textContent = JSON.stringify({ ...payload, access_map: state.accessMap }, null, 2);
}

function renderFindings() {
  const tbody = findingsTable.querySelector('tbody');
  tbody.innerHTML = '';
  if (state.findings.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4">No findings yet.</td></tr>';
    return;
  }

  state.findings.slice(0, 50).forEach((f) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(f.rule?.name || '')}</td>
      <td>${escapeHtml(f.rule?.id || '')}</td>
      <td>${escapeHtml(f.finding?.path || '')}</td>
      <td><span class="badge ${classForConfidence(f.finding?.confidence)}">${escapeHtml(
        f.finding?.confidence || ''
      )}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderAccessMap(rows) {
  const tbody = accessTable.querySelector('tbody');
  tbody.innerHTML = '';
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4">No access-map entries yet.</td></tr>';
    return;
  }

  rows.forEach((row) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${escapeHtml(row.provider || '')}</td>
      <td>${escapeHtml(row.account || '')}</td>
      <td>${escapeHtml(row.resource || '')}</td>
      <td>${escapeHtml(row.permissions.join(', ') || '')}</td>
    `;
    tbody.appendChild(tr);
  });
}

function escapeHtml(str = '') {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function classForConfidence(conf = '') {
  const c = conf.toLowerCase();
  if (c === 'high') return 'badge-warn';
  if (c === 'medium') return 'badge';
  if (c === 'low') return 'badge-good';
  return 'badge';
}

function normalizeAccessMap(entries = []) {
  if (!Array.isArray(entries)) return [];

  // Already in new schema
  if (entries.some((e) => Array.isArray(e.groups))) {
    return entries.map((entry) => ({
      provider: entry.provider,
      account: entry.account,
      mappingError: entry.mapping_error ?? entry.mappingError ?? null,
      groups: (entry.groups || []).map((group) => ({
        resources: Array.isArray(group.resources) ? group.resources : [],
        permissions: Array.isArray(group.permissions) ? group.permissions : [],
      })),
    }));
  }

  // Fallback for legacy flat entries
  return entries.map((entry) => {
    const permissions = Array.isArray(entry.permissions)
      ? entry.permissions
      : entry.permission
        ? String(entry.permission)
            .split(',')
            .map((p) => p.trim())
            .filter(Boolean)
        : [];
    const resource = entry.resource ? [entry.resource] : [];
    return {
      provider: entry.provider,
      account: entry.account,
      mappingError: entry.mapping_error ?? entry.mappingError ?? null,
      groups: [{ resources: resource, permissions }],
    };
  });
}

function flattenAccessMap(entries = []) {
  const rows = [];
  entries.forEach((entry) => {
    // A failed mapping resolved nothing; its groups are placeholders.
    if (entry.mappingError) return;
    (entry.groups || []).forEach((group) => {
      (group.resources || []).forEach((resource) => {
        rows.push({
          provider: entry.provider,
          account: entry.account,
          resource,
          permissions: group.permissions || [],
        });
      });
    });
  });
  return rows;
}
