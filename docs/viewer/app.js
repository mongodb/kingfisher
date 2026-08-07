let rawData = null;
let findings = [];
let accessMap = [];
let currentFilter = "";
let validationFilter = "all";
let pageSize = 10;
let currentPage = 1;
let sortField = "rule";
let sortDirection = "asc";

const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("file-input");
const loader = document.getElementById("loader");
const loaderText = document.getElementById("loader-text");
const errorMsg = document.getElementById("error-msg");
const uploadSection = document.getElementById("upload-section");
const dashboard = document.getElementById("dashboard");

const searchInput = document.getElementById("search-input");
const validationSelect = document.getElementById("validation-filter");
const rowsSelect = document.getElementById("rows-select");
const pagePrev = document.getElementById("page-prev");
const pageNext = document.getElementById("page-next");
const pageInfo = document.getElementById("page-info");
const findingsBody = document.getElementById("findings-body");

const resetButton = document.getElementById("reset-btn");

const treeSearch = document.getElementById("tree-search");
const amContainer = document.getElementById("am-container");
const amToggle = document.getElementById("am-toggle");

dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", (e) => {
  if (e.target.files.length) processFile(e.target.files[0]);
});
dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("active");
});
dropZone.addEventListener("dragleave", (e) => {
  e.preventDefault();
  dropZone.classList.remove("active");
});
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("active");
  if (e.dataTransfer.files.length) processFile(e.dataTransfer.files[0]);
});

if (resetButton) {
  resetButton.addEventListener("click", () => {
    rawData = null;
    findings = [];
    accessMap = [];
    currentFilter = "";
    validationFilter = "all";
    pageSize = 10;
    currentPage = 1;
    sortField = "rule";
    sortDirection = "asc";

    searchInput.value = "";
    validationSelect.value = "all";
    rowsSelect.value = "10";
    treeSearch.value = "";
    amContainer.classList.remove("hidden");
    amToggle.textContent = "Collapse";

    findingsBody.innerHTML = "";
    document.getElementById("access-tree").innerHTML =
      '<div style="color:var(--text-muted); font-size:13px; text-align:center; margin-top:32px;">No access map data found in report.</div>';

    resetError();
    uploadSection.classList.remove("hidden");
    dashboard.classList.add("hidden");
    setLoading(false);
  });
}

searchInput.addEventListener("input", () => {
  currentFilter = searchInput.value.trim().toLowerCase();
  currentPage = 1;
  renderTable();
});

validationSelect.addEventListener("change", () => {
  validationFilter = validationSelect.value;
  currentPage = 1;
  renderTable();
});

rowsSelect.addEventListener("change", () => {
  pageSize = parseInt(rowsSelect.value, 10);
  currentPage = 1;
  renderTable();
});

pagePrev.addEventListener("click", () => {
  if (currentPage > 1) {
    currentPage--;
    renderTable();
  }
});

pageNext.addEventListener("click", () => {
  const totalPages = Math.max(1, Math.ceil(filteredFindings().length / pageSize));
  if (currentPage < totalPages) {
    currentPage++;
    renderTable();
  }
});

amToggle.addEventListener("click", () => {
  amContainer.classList.toggle("hidden");
  amToggle.textContent = amContainer.classList.contains("hidden") ? "Show Access Map" : "Hide Access Map";
});

function processFile(file) {
  resetError();
  setLoading(true, `Reading ${file.name}...`);

  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      rawData = e.target.result;
      parseData(rawData);
    } catch (err) {
      setError(`Failed to read file: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };
  reader.onerror = () => {
    setError("Error reading file. Please try again.");
    setLoading(false);
  };
  reader.readAsText(file);
}

async function loadEmbeddedReport() {
  try {
    setLoading(true, "Loading CLI report...");
    const response = await fetch("/report", { cache: "no-store" });

    if (response.status === 404) {
      setLoading(false);
      return;
    }

    if (!response.ok) {
      throw new Error(`server returned ${response.status}`);
    }

    const text = await response.text();
    rawData = text;
    await parseData(text);
  } catch (err) {
    setLoading(false);
    setError(`Failed to load report from CLI: ${err.message}`);
  }
}

async function parseData(text) {
  const parsed = parsePayload(text);
  findings = parsed.findings.map(normalizeFinding);
  accessMap = flattenAccessMap(normalizeAccessMap(parsed.access_map));

  renderStats();
  buildAccessTree(accessMap);
  renderTable();
  showDashboard();
}

function parsePayload(text) {
  try {
    const parsed = JSON.parse(text);
    return collectReportData(parsed);
  } catch (_) {
    return collectReportDataFromJsonl(text);
  }
}

function collectReportData(root) {
  const findings = [];
  const accessMap = [];

  const visit = (node) => {
    if (node === null || node === undefined) return;

    if (Array.isArray(node)) {
      for (const item of node) {
        visit(item);
      }
      return;
    }

    if (typeof node !== "object") return;

    if (node.rule && node.finding) {
      findings.push(node);
    }

    if (Array.isArray(node.findings)) {
      findings.push(...node.findings);
    }

    if (Array.isArray(node.access_map)) {
      accessMap.push(...node.access_map);
    }

    Object.values(node).forEach(visit);
  };

  visit(root);

  if (!findings.length && Array.isArray(root)) {
    findings.push(...root);
  }

  return { findings, access_map: accessMap };
}

function collectReportDataFromJsonl(text) {
  const findings = [];
  const accessMap = [];
  const lines = text.split(/\r?\n/).filter(Boolean);

  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      const parsed = collectReportData(obj);
      findings.push(...parsed.findings);
      accessMap.push(...parsed.access_map);
    } catch (_) {
      /* ignore invalid lines */
    }
  }

  return { findings, access_map: accessMap };
}

function normalizeFinding(row) {
  const validation = row.finding?.validation || row.validation || {};
  return {
    ruleId: `${row.rule?.id ?? ""}`,
    ruleName: `${row.rule?.name ?? ""}`,
    findingType: `${row.finding?.type ?? row.finding?.category ?? ""}`,
    severity: `${row.finding?.severity ?? row.severity ?? ""}`,
    message: `${row.finding?.message ?? row.finding?.snippet ?? ""}`,
    path: `${row.finding?.path ?? row.path ?? ""}`,
    line: `${row.finding?.line ?? row.finding?.start?.line ?? ""}`,
    validationStatus: `${validation.status ?? ""}`,
    validationConfidence: `${validation.confidence ?? ""}`,
    validationResponse: `${validation.response ?? ""}`,
    confidence: `${row.finding?.confidence ?? ""}`,
    snippet: `${row.finding?.snippet ?? ""}`,
    fingerprint: `${row.finding?.fingerprint ?? ""}`,
    raw: row,
  };
}

function normalizeAccessMap(entries = []) {
  if (!Array.isArray(entries)) return [];

  if (entries.some((entry) => Array.isArray(entry.groups))) {
    return entries.map((entry) => ({
      provider: entry.provider,
      account: entry.account,
      fingerprint: entry.fingerprint,
      groups: (entry.groups || []).map((group) => ({
        resources: Array.isArray(group.resources) ? group.resources : [],
        permissions: Array.isArray(group.permissions) ? group.permissions : [],
      })),
    }));
  }

  return entries.map((entry) => ({
    provider: entry.provider,
    account: entry.account,
    fingerprint: entry.fingerprint,
    groups: [
      {
        resources: entry.resource ? [entry.resource] : [],
        permissions: Array.isArray(entry.permissions)
          ? entry.permissions
          : entry.permission
            ? String(entry.permission)
              .split(",")
              .map((p) => p.trim())
              .filter(Boolean)
            : [],
      },
    ],
  }));
}

function flattenAccessMap(entries = []) {
  const rows = [];
  entries.forEach((entry) => {
    (entry.groups || []).forEach((group) => {
      (group.resources || []).forEach((resource) => {
        rows.push({
          provider: entry.provider,
          account: entry.account,
          fingerprint: entry.fingerprint,
          resource,
          permissions: group.permissions || [],
        });
      });
    });
  });
  return rows;
}

function renderStats() {
  const totalFindings = findings.length;
  const criticalCount = findings.filter((f) => f.severity.toLowerCase() === "critical").length;
  const highCount = findings.filter((f) => f.severity.toLowerCase() === "high").length;
  const mediumCount = findings.filter((f) => f.severity.toLowerCase() === "medium").length;
  const validatedCount = findings.filter((f) => !!f.validationStatus).length;

  document.getElementById("stat-findings").textContent = totalFindings;
  document.getElementById("stat-critical").textContent = criticalCount;
  document.getElementById("stat-high").textContent = highCount;
  document.getElementById("stat-medium").textContent = mediumCount;
  document.getElementById("stat-validated").textContent = validatedCount;
  document.getElementById("stat-access-map").textContent = accessMap.length;
}

function renderTable() {
  const rows = filteredFindings();

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  currentPage = Math.min(currentPage, totalPages);

  pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
  pagePrev.disabled = currentPage === 1;
  pageNext.disabled = currentPage === totalPages;

  const start = (currentPage - 1) * pageSize;
  const end = start + pageSize;
  const pageRows = rows.slice(start, end);

  findingsBody.innerHTML = pageRows
    .map((f) => `
      <tr>
        <td class="nowrap">${escapeHtml(f.ruleId)}</td>
        <td class="nowrap">${escapeHtml(f.ruleName)}</td>
        <td class="nowrap">${escapeHtml(f.findingType)}</td>
        <td class="nowrap">${escapeHtml(f.severity)}</td>
        <td>${escapeHtml(f.message)}</td>
        <td>${escapeHtml(f.path)}</td>
        <td>${escapeHtml(f.line)}</td>
        <td>${escapeHtml(f.validationStatus)}</td>
        <td>${escapeHtml(f.validationConfidence)}</td>
      </tr>
    `)
    .join("");
}

function filteredFindings() {
  return findings
    .filter((f) => {
      if (
        validationFilter === "active" &&
        !["verified active credential", "active credential"].includes(f.validationStatus.toLowerCase())
      ) return false;
      if (validationFilter === "inactive" && f.validationStatus.toLowerCase() !== "inactive credential") return false;
      if (validationFilter === "not_attempted" && f.validationStatus.toLowerCase() !== "not attempted") return false;

      if (!currentFilter) return true;
      const haystack = `${f.ruleId} ${f.ruleName} ${f.findingType} ${f.message} ${f.path} ${f.validationStatus} ${f.fingerprint}`.toLowerCase();
      return haystack.includes(currentFilter);
    })
    .sort((a, b) => {
      const av = getSortValue(a, sortField);
      const bv = getSortValue(b, sortField);
      if (av === bv) return 0;
      return sortDirection === "asc" ? (av > bv ? 1 : -1) : av < bv ? 1 : -1;
    });
}

function getSortValue(obj, field) {
  switch (field) {
    case "rule":
      return `${obj.ruleId}`.toLowerCase();
    case "location":
      return `${obj.path}`.toLowerCase();
    case "severity":
      return `${obj.severity}`.toLowerCase();
    case "validation":
      return `${obj.validationStatus}`.toLowerCase();
    case "confidence":
      return `${obj.confidence}`.toLowerCase();
    case "line":
      return `${obj.line}`.toLowerCase();
    default:
      return `${obj.path}`.toLowerCase();
  }
}

document.querySelectorAll("th.sortable").forEach((th) => {
  th.addEventListener("click", () => {
    const field = th.dataset.sort;
    if (sortField === field) {
      sortDirection = sortDirection === "asc" ? "desc" : "asc";
    } else {
      sortField = field;
      sortDirection = "asc";
    }
    document
      .querySelectorAll("th.sortable")
      .forEach((el) => el.classList.toggle("sorted", el.dataset.sort === sortField));
    renderTable();
  });
});

treeSearch.addEventListener("input", () => buildAccessTree(accessMap));

function buildAccessTree(entries) {
  const search = treeSearch.value.trim().toLowerCase();
  const tree = document.getElementById("access-tree");
  tree.innerHTML = "";

  if (!entries.length) {
    tree.innerHTML = "<p style=\"color:var(--text-muted);\">No access map entries.</p>";
    return;
  }

  const filtered = entries.filter((entry) =>
    [entry.provider, entry.account, entry.resource, ...(entry.permissions || [])]
      .join(" ")
      .toLowerCase()
      .includes(search)
  );

  const grouped = {};
  for (const entry of filtered) {
    const provider = entry.provider || "Unknown";
    const account = entry.account || "Unknown";
    grouped[provider] = grouped[provider] || {};
    grouped[provider][account] = grouped[provider][account] || [];
    grouped[provider][account].push(entry);
  }

  Object.entries(grouped).forEach(([provider, accounts]) => {
    const providerEl = document.createElement("div");
    providerEl.className = "tree-node";
    providerEl.innerHTML = `<div class="tree-node__label">${escapeHtml(provider)}</div>`;

    Object.entries(accounts).forEach(([account, resources]) => {
      const accountEl = document.createElement("div");
      accountEl.className = "tree-node tree-node--child";
      accountEl.innerHTML = `<div class="tree-node__label">${escapeHtml(account)}</div>`;

      resources.forEach((r) => {
        const resEl = document.createElement("div");
        resEl.className = "tree-node tree-node--grandchild";
        resEl.innerHTML = `
          <div class="tree-node__label">${escapeHtml(r.resource || "(resource)")}</div>
          <div class="tree-badge">${escapeHtml((r.permissions || []).join(", "))}</div>
        `;
        accountEl.appendChild(resEl);
      });

      providerEl.appendChild(accountEl);
    });

    tree.appendChild(providerEl);
  });
}

function setLoading(enabled, message = "Loading...") {
  loader.classList.toggle("hidden", !enabled);
  loaderText.textContent = message;
}

function setError(message) {
  errorMsg.textContent = message;
  errorMsg.classList.remove("hidden");
  uploadSection.classList.add("error");
}

function resetError() {
  errorMsg.textContent = "";
  errorMsg.classList.add("hidden");
  uploadSection.classList.remove("error");
}

function showDashboard() {
  uploadSection.classList.add("hidden");
  dashboard.classList.remove("hidden");
  setLoading(false);
}

function escapeHtml(str) {
  return (str || "")
    .toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function downloadJson() {
  if (!rawData) return;
  const blob = new Blob([rawData], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "access-map-report.json";
  a.click();
  URL.revokeObjectURL(url);
}

function copyAccessMap() {
  if (!accessMap.length) return;
  const text = JSON.stringify(accessMap, null, 2);
  navigator.clipboard.writeText(text).catch(() => { });
}

function exportCsv() {
  const rows = filteredFindings();
  if (!rows.length) return;

  const header = [
    "rule_id",
    "rule_name",
    "finding_type",
    "severity",
    "message",
    "path",
    "line",
    "validation_status",
    "validation_confidence",
  ];

  const csv = [header.join(",")]
    .concat(
      rows.map((f) =>
        [
          f.ruleId,
          f.ruleName,
          f.findingType,
          f.severity,
          escapeCsv(f.message),
          f.path,
          f.line,
          f.validationStatus,
          f.validationConfidence,
        ].join(",")
      )
    )
    .join("\n");

  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "access-map-findings.csv";
  a.click();
  URL.revokeObjectURL(url);
}

function escapeCsv(value) {
  const str = value.replace(/"/g, '""');
  return `"${str}"`;
}

document.getElementById("download-json").addEventListener("click", downloadJson);
document.getElementById("download-csv").addEventListener("click", exportCsv);
document.getElementById("copy-access-map").addEventListener("click", copyAccessMap);

loadEmbeddedReport();
