const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const html = fs.readFileSync(require("node:path").join(__dirname, "../docs/viewer/index.html"), "utf8");
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)].map(m => m[1]);
for (const script of scripts) new vm.Script(script);
// Load top-level function declarations without running browser initialization.
const functions = scripts.join("\n").match(/^    function \w+\([^]*?^    }/gm);
const ctx = vm.createContext({});
vm.runInContext(functions.join("\n"), ctx);
const gitleaks = (file, secret) => ctx.normalizeGitleaksFinding({
  RuleID: "demo", Description: "Generic description", File: file, Secret: secret,
});
const trufflehog = (file, secret) => ctx.normalizeTruffleHogFinding({
  DetectorName: "Demo", DetectorDescription: "Generic description", File: file, Raw: secret,
});
for (const normalize of [gitleaks, trufflehog]) {
  const a = normalize("a.txt");
  const b = normalize("b.txt");
  assert.notEqual(ctx.secretGroupKey(a), ctx.secretGroupKey(b));
  assert.equal(ctx.secretGroupKey(normalize("a.txt", "secret")), ctx.secretGroupKey(normalize("b.txt", "secret")));
}
const run = { tool: { driver: { name: "Example" } } };
const sarif = file => ctx.normalizeSarifResult({
  ruleId: "demo", message: { text: "Generic description" },
  locations: [{ physicalLocation: { artifactLocation: { uri: file }, region: { startLine: 1 } } }],
}, run, { byId: new Map(), byIndex: [] });
assert.notEqual(ctx.secretGroupKey(sarif("a.txt")), ctx.secretGroupKey(sarif("b.txt")));
const a = gitleaks("a.txt", "secret");
const b = trufflehog("b.txt", "secret");
a.finding.fingerprint = b.finding.fingerprint = "shared";
const result = ctx.deduplicateFindings([a, b, a]);
assert.equal(result.findings.length, 2);
assert.equal(result.dropped.total, 1);
const otherSarif = sarif("a.txt");
otherSarif.finding.viewer_import.source_tool = "Another scanner";
const originalSarif = sarif("a.txt");
originalSarif.finding.fingerprint = otherSarif.finding.fingerprint = "shared";
assert.equal(ctx.deduplicateFindings([originalSarif, otherSarif]).findings.length, 2);
console.log("Viewer script syntax and import grouping regressions passed.");

// Render a collapsed group: every distinct status must remain visible regardless of order.
ctx.expandedSecretGroups = new Set();
ctx.document = { createElement: () => ({ setAttribute() {}, addEventListener() {} }) };
vm.runInContext("addViewerSelection = () => {};", ctx);
const occurrence = status => ({ rule: { id: "demo" }, finding: {
  snippet: "same-secret", validation: { status },
} });
for (const statuses of [
  ["Inactive Credential", "Active Credential"],
  ["Active Credential", "Inactive Credential"],
  ["Inactive Credential", undefined],
  ["Active Credential", "verified active credential"],
]) {
  const group = ctx.groupFindingsBySecret(statuses.map(occurrence))[0];
  const row = ctx.buildGroupRow(group);
  const labels = [...row.innerHTML.matchAll(/class="status-badge [^"]+">([^<]+)<\/span>/g)].map(m => m[1]);
  const expected = [...new Set(statuses.map(status => ctx.validationStatusLabel(status)))];
  assert.deepEqual([...labels].sort(), expected.sort());
}
console.log("Collapsed group validation status regressions passed.");

// Native SARIF commands remain usable when a third-party import disables global capabilities.
ctx.scanMetadata = { capabilities: { validateCommandSupported: false, revokeCommandSupported: false } };
for (const kind of ["validation", "revocation"]) {
  const field = kind === "revocation" ? "revoke_command" : "validate_command";
  const native = { finding: { viewer_import: { kingfisher_native: true }, [field]: "native-command" } };
  assert.equal(ctx.viewerActionCommand(native, kind), "native-command");
  native.finding.viewer_import.kingfisher_native = false;
  assert.equal(ctx.viewerActionCommand(native, kind), "");

  // A commit/path/line match can still refer to a different credential on that line.
  const source = { rule: { id: "demo" }, finding: {
    path: "config.txt", line: 1, snippet: "secret-A", git_metadata: { commit: { id: "abc" } },
    [field]: "command-for-secret-A",
  } };
  const imported = { finding: {
    path: "config.txt", line: 1, snippet: "secret-B", git_metadata: { commit: { id: "abc" } },
    viewer_import: { source_tool: "gitleaks" },
  } };
  ctx.enrichImportedFindings([source, imported]);
  assert.equal(imported.finding.kingfisher_enrichment.match_strength, "commit");
  assert.equal(ctx.viewerActionCommand(imported, kind), "");
  const copied = [];
  ctx.document = { getElementById: () => ({ classList: { add() {}, remove() {} } }) };
  ctx.wireKfEnrichmentCopyButton = (...args) => copied.push(args[3]);
  ctx.renderKingfisherEnrichment(imported.finding);
  assert.deepEqual(copied, ["", ""]);
}
console.log("Viewer native command and unsafe enrichment regressions passed.");

// Provider labels remain text in rationale HTML for native and SARIF reports.
for (const [provider, expected] of [
  ["aws", "AWS"],
  ['<em title="example">a&b</em>', "&lt;EM TITLE=&quot;EXAMPLE&quot;&gt;A&amp;B&lt;/EM&gt;"],
  ["&#60;em&#62;example&#60;/em&#62;", "&amp;#60;EM&amp;#62;EXAMPLE&amp;#60;/EM&amp;#62;"],
  [42, "42"],
]) {
  const access = { fingerprint: "provider-label", provider, groups: [
    { resources: ["example-resource"], permissions: ["read"] },
  ] };
  const native = { findings: [{ rule: { id: "example", name: "Example" }, finding: {
    fingerprint: access.fingerprint, validation: { status: "Active Credential" },
  } }], access_map: [access, access] };
  const sarifReport = { version: "2.1.0", runs: [{
    tool: { driver: { name: "Example" } },
    properties: { access_map: [access, access] },
    results: [{ ruleId: "example", message: { text: "Example" },
      partialFingerprints: { fingerprint: access.fingerprint },
      properties: { validation_status: "Active Credential" },
    }],
  }] };
  for (const payload of [native, sarifReport]) {
    const normalized = ctx.normalizeReportPayload(payload);
    const finding = normalized.f[0];
    const entries = normalized.am.filter(entry => entry.fingerprint === finding.finding.fingerprint);
    assert.equal(entries.length, 2);
    const { text } = ctx.generateRiskRationale(finding, entries);
    assert.ok(text.includes(` on ${expected}.`), text);
    assert.ok(text.includes("<strong>"), "Intentional rationale formatting is preserved");
    assert.ok(!text.includes("<EM"), "Provider labels cannot introduce HTML elements");
  }
}
console.log("Viewer provider label rendering regressions passed.");
