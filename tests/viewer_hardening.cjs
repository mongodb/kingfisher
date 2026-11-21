const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../docs/viewer/index.html'), 'utf8');
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\b[^>]*>/gi)].map(m => m[1]);
const ctx = vm.createContext({ URL, accessMapByFindingFingerprint: new Map() });
vm.runInContext(scripts.join('\n').match(/^    function \w+\([^]*?^    }/gm).join('\n'), ctx);

for (const url of ['https://example.com/profile', 'http://localhost:8000/path', 'HTTPS://example.com']) {
  assert.equal(ctx.isHttpUrl(url), true, url);
}
for (const url of ['javascript:alert(1)', 'java\nscript:alert(1)', 'data:text/html,example',
  'file:///tmp/report', '//example.com', 'https://', 'https://user:pass@example.com', null, {}]) {
  assert.equal(ctx.isHttpUrl(url), false, String(url));
}

const elements = [];
function element(tag) {
  const el = { tag, children: [], style: {}, dataset: {}, classList: { add() {}, remove() {}, toggle() {} },
    appendChild(child) { this.children.push(child); return child; },
    append(...children) { this.children.push(...children); },
    insertAdjacentHTML(position, markup) { assert.equal(position, 'beforeend'); this.children.push(markup); },
    setAttribute() {}, addEventListener() {}, querySelector() { return null; },
  };
  elements.push(el);
  return el;
}
ctx.document = { createElement: element };
ctx.localStorage = { getItem: () => null };
ctx.AM_CRITICAL_KEY = 'test-critical';
ctx.expandedAccessKeys = new Set(['url-test']);
vm.runInContext('addViewerSelection = () => {};', ctx);
const label = '<em>example</em>';
const finding = { rule: { id: '__proto__', name: 'Example' }, finding: {
  line: label, path: 'example.txt', snippet: 'example', fingerprint: 'example',
  validation: { status: 'Active Credential' },
} };
const row = ctx.buildFindingRow(finding);
assert.ok(row.innerHTML.includes('&lt;em&gt;example&lt;/em&gt;'));
assert.ok(!row.innerHTML.includes(label));

for (const url of ['javascript:alert(1)', 'https://example.com/profile']) {
  elements.length = 0;
  ctx.buildIdentityCard({ key: 'url-test', identity: { provider: 'aws', account: 'Example', token_details: { url } }, groups: [] });
  const links = elements.filter(el => el.tag === 'a');
  assert.equal(links.length, url.startsWith('https:') ? 1 : 0);
  if (links.length) assert.equal(links[0].rel, 'noopener noreferrer');
}
const severity = ctx.summarizeSeverity({ identity: { permissions_by_severity: {
  admin: { length: label }, risky: ['read'], read_only: 'text',
} } });
assert.equal(severity.admin, 0);
assert.equal(severity.risky, 1);
assert.equal(severity.read_only, 0);

ctx.findings = [finding];
ctx.setAccessMap([{ fingerprint: 'primary', finding_fingerprints: ['primary', 'example'], provider: 'aws', groups: [],
  token_details: { last_used_at: '2026-01-02T00:01:02Z' },
  provider_metadata: { credential_last_used_source: 'Provider audit <latest event>' } }]);
const standaloneHtml = fs.readFileSync(path.join(__dirname, '../src/access_map/report.rs'), 'utf8');
vm.runInContext(standaloneHtml.match(/^    function renderLastUsed\([^]*?^    }/m)[0], ctx);
const standaloneLastUse = ctx.renderLastUsed(ctx.accessMap[0]);
assert.equal(standaloneLastUse.children[1].dateTime, '2026-01-02T00:01:02.000Z');
assert.equal(standaloneLastUse.children[2].className, 'credential-last-used-source');
assert.equal(standaloneLastUse.children[2].textContent, 'Provider audit <latest event>');
assert.equal(ctx.renderLastUsed({ provider_metadata: ctx.accessMap[0].provider_metadata }).children[1], 'Unavailable');
ctx.scanMetadata = {};
ctx.repositoryAudit = null;
ctx.statusChartCanvas = null;
ctx.setTimeout = () => {};
let output, printHandler, printCount;
ctx.window = { open() {
  output = ''; printHandler = null; printCount = 0;
  return { document: {
    write(value) { output = value; }, close() {},
    getElementById(id) {
      assert.equal(id, 'report-print');
      assert.ok(output.includes('id="report-print"'));
      return { addEventListener(event, handler) { assert.equal(event, 'click'); printHandler = handler; } };
    },
  }, focus() {}, print() { printCount++; } };
} };
for (const [generate, showsLastUse] of [[() => ctx.generateScanReport(), false], [() => ctx.generateAccessMapReport(), true],
  [() => ctx.exportSingleFindingRiskReport(finding), true], [() => ctx.generateRiskReport(), false]]) {
  generate();
  assert.ok(output.includes('<!doctype html>'));
  assert.ok(!output.includes(label));
  assert.ok(!/\sonclick\s*=/i.test(output));
  if (showsLastUse) {
    assert.ok(output.includes('.credential-last-used {'));
    assert.match(output, /<strong>Last used<\/strong> <time datetime="2026-01-02T00:01:02\.000Z">/);
    assert.ok(output.includes('<span class="credential-last-used-source">Provider audit &lt;latest event&gt;</span>'));
  }
  assert.equal(typeof printHandler, 'function');
  printHandler();
  assert.equal(printCount, 1);
}
console.log('Viewer URL, text rendering, severity, and print regressions passed.');
