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
