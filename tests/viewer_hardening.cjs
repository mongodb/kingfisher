const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../docs/viewer/index.html'), 'utf8');
function extractScripts(source) {
  return [...source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\b[^>]*>/gi)].map(m => m[1]);
}
for (const closingTag of ['</script>', '</SCRIPT >', '</script\t\n bar>']) {
  assert.deepEqual(extractScripts(`<script>example();${closingTag}<p>after</p>`), ['example();']);
}
const scripts = extractScripts(html);
for (const script of scripts) new vm.Script(script);
const ctx = vm.createContext({ URL });
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
    setAttribute() {}, addEventListener() {}, querySelector() { return null; },
  };
  elements.push(el);
  return el;
}
ctx.document = { createElement: element };
ctx.localStorage = { getItem: () => null };
ctx.AM_CRITICAL_KEY = 'test-critical';
ctx.expandedAccessKeys = new Set();
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
  ctx.buildIdentityCard({ identity: { provider: 'aws', account: 'Example', token_details: { url } }, groups: [] });
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
ctx.accessMap = [{ fingerprint: 'example', provider: 'aws', groups: [] }];
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
for (const generate of [() => ctx.generateScanReport(), () => ctx.generateAccessMapReport(),
  () => ctx.exportSingleFindingRiskReport(finding), () => ctx.generateRiskReport()]) {
  generate();
  assert.ok(output.includes('<!doctype html>'));
  assert.ok(!output.includes(label));
  assert.ok(!/\sonclick\s*=/i.test(output));
  assert.equal(typeof printHandler, 'function');
  printHandler();
  assert.equal(printCount, 1);
}
console.log('Viewer URL, text rendering, severity, and print regressions passed.');
