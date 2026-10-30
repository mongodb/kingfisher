const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../docs/viewer/index.html'), 'utf8');
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\b[^>]*>/gi)].map(match => match[1]);
for (const script of scripts) new vm.Script(script);
// Collection-time caveats must remain visible after opening a snapshot, and
// graph hints must use the actual view-switch label.
assert.ok(!/body:not\(\.workspace-empty\)\s+\.workspace-context\s*\{[^}]*display:\s*none/.test(html));
assert.ok(!html.includes('Open Details for the complete list.'));
assert.ok(!html.includes('available in Details.</div>'));
assert.ok(html.includes('Open Investigate for the complete list.'));
// Details opened from the overview must not inherit a hidden tab panel.
const sectionStack = [];
let modalSections;
for (const [tag] of html.matchAll(/<\/?section\b[^>]*>|<div\b[^>]*\bid="finding-detail"[^>]*>/g)) {
  if (tag.startsWith('</')) sectionStack.pop();
  else if (tag.startsWith('<section')) sectionStack.push(tag);
  else { modalSections = [...sectionStack]; break; }
}
assert.ok(modalSections, 'Finding detail modal is present');
assert.ok(!modalSections.some(tag => /\brole="tabpanel"/.test(tag)), 'Shared finding details must remain visible outside the Findings tab');
const context = vm.createContext({ URL, URLSearchParams, Intl });
vm.runInContext(scripts.join('\n').match(/^    (?:async )?function \w+\([^]*?^    }/gm).join('\n'), context);
context.scanMetadata = {};
const entry = (evidence = {}, overrides = {}) => ({
  provider: 'aws', account: 'Example identity', fingerprint: 'example',
  groups: [{ resources: ['example-resource'], permissions: ['s3:GetObject'] }],
  provider_metadata: { authorization_evidence: evidence }, ...overrides,
});
const finding = { rule: { name: 'Example credential' }, finding: { validation: { status: 'Active Credential' } } };

// Resource volume and wildcards are not capability-risk evidence.
const metadataOnly = entry({}, { groups: [{ resources: Array.from({ length: 100 }, (_, index) => `resource-${index}`), permissions: ['s3:List*'] }] });
assert.equal(context.investigationRisk(metadataOnly), 'unknown');
assert.equal(context.generateRiskRationale(finding, [metadataOnly]).level, 'none');
assert.ok(!context.generateRiskRationale(finding, [metadataOnly]).text.includes('grants access'));
const oldRead = entry({}, { permissions_by_severity: { read_only: ['s3:List*'] } });
assert.equal(context.generateRiskRationale(finding, [oldRead]).level, 'low');
const explicitRisk = entry({ assessment: { capability_risk: 'high', legacy_severity: 'low', coverage: 'partial' } });
assert.equal(context.generateRiskRationale(finding, [explicitRisk]).level, 'high');
assert.match(context.generateRiskRationale(finding, []).text, /unknown/);

// Empty enumeration may identify a principal without establishing resource access.
const identityOnly = entry({}, { context: { identity_id: 'arn:example:identity' }, groups: [{ resources: ['arn:example:identity'], permissions: [] }] });
assert.equal(context.countResources([identityOnly]), 0);
assert.equal(context.investigationResourceNames(metadataOnly).length, 100);

// Confidence facets keep observed method acceptance separate from policies and candidates.
const narrowObservation = entry({ probes: [{ service: 'storage', method: 'ListBuckets', status: 'accepted' }], assessment: { capability_risk: 'low', capabilities: [{ permission: 's3:ListAllMyBuckets', category: 'metadata_read', reach: 'direct', evidence: 'observed', scope: '*' }] } });
assert.deepEqual([...context.investigationEvidence(narrowObservation).kinds], ['observed']);
assert.equal(context.investigationRisk(narrowObservation), 'low');
assert.match(context.generateRiskRationale(finding, [narrowObservation]).text, /recorded method and scope/);
const candidate = entry({ paths: [{ status: 'trust_only', hops: [{ from: 'A', to: 'B', relationship: 'trusts' }], conditions: ['MFA'], evidence: ['policy:example'] }] });
assert.deepEqual([...context.investigationEvidence(candidate).kinds], ['conditional']);
assert.equal(context.investigationRisk(candidate), 'unknown');
assert.match(context.investigationEvidenceHtml(candidate).html, /trust_only/);

// Policy provenance retains negative semantics and renders untrusted material as text.
const malicious = '<img src=x onerror=alert(1)>';
const policy = entry({ policies: [{ id: 'policy-a', kind: 'resource', attached_to: 'principal-a', attached_via: 'group-a', scope: 'bucket-a', statements: [{
  id: 'statement-a', effect: 'Allow', actions: ['s3:GetObject'], not_actions: ['s3:DeleteObject'], resources: ['bucket/*'], not_resources: ['bucket/private/*'],
  principals: ['principal-a'], not_principals: ['principal-b'], condition_keys: ['StringEquals:aws:PrincipalTag/team', malicious],
}] }] });
const rendered = context.investigationEvidenceHtml(policy).html;
for (const expected of ['Except actions', 'Except resources', 'Except principals', 'Condition keys', 'Attached to', 'Via', 's3:DeleteObject', 'bucket/private/*', 'principal-b']) assert.ok(rendered.includes(expected), expected);
assert.ok(rendered.includes('&lt;img'));
assert.ok(!rendered.includes(malicious));
assert.ok(context.investigationEvidenceHtml(policy, 'principal-b').html.includes('Except principals'));
assert.match(context.investigationEvidenceHtml(policy, 'absent-needle').html, /No matching authorization evidence/);

// Both outer collections and nested policy statements are bounded and expandable.
const manyPaths = entry({ paths: Array.from({ length: 60 }, (_, index) => ({ status: 'potential', hops: [{ from: 'A', to: `target-${index}`, relationship: 'may_assume' }] })) });
const firstPage = context.investigationEvidenceHtml(manyPaths, '', 25);
assert.equal(firstPage.truncated, true);
assert.ok(!firstPage.html.includes('target-59'));
assert.ok(context.investigationEvidenceHtml(manyPaths, '', 75).html.includes('target-59'));
const manyStatements = entry({ policies: [{ id: 'large-policy', statements: Array.from({ length: 60 }, (_, index) => ({ id: `statement-${index}`, effect: 'Allow', actions: [`action-${index}`] })) }] });
assert.equal(context.investigationEvidenceHtml(manyStatements, '', 25).truncated, true);
assert.ok(context.investigationEvidenceHtml(manyStatements, 'action-59', 25).html.includes('action-59'));
const policyNameSearch = context.investigationEvidenceHtml(manyStatements, 'large-policy', 25);
assert.ok(policyNameSearch.html.includes('action-0'));
assert.equal(policyNameSearch.truncated, true);
assert.ok(context.investigationEvidenceHtml(manyStatements, 'large-policy', 75).html.includes('action-59'));
const namedRole = entry({ role_impacts: [{ role: 'DeployRole', grants: [{ permissions: ['iam:*'], resources: ['*'] }] }] });
assert.ok(context.investigationEvidenceHtml(namedRole, 'DeployRole').html.includes('iam:*'));
assert.ok(context.investigationEvidenceHtml(policy, 'policy-a').html.includes('s3:GetObject'));
assert.ok(!context.investigationEvidenceHtml(manyStatements, 'action-59', 25).html.includes('<code>action-0</code>'));

// Detailed assessment data remains optional, searchable, and carries provider rationale.
const detailed = entry({ assessment: { capability_risk: 'high', coverage: 'partial', capabilities: [{ permission: 'secretmanager.versions.access', category: 'sensitive_read', evidence: 'policy_grant', reach: 'reachable', scope: 'projects/example' }], resources: [{ resource_type: 'secret', name: 'example-secret', permissions: ['read'], risk: 'high', reason: 'Visible role grant' }], recommendations: ['Rotate after review'], risk_notes: ['Condition values not evaluated'] } });
const detailsHtml = context.investigationEvidenceHtml(detailed).html;
for (const expected of ['Sensitive data read', 'Candidate role path', 'Policy grant', 'example-secret', 'Visible role grant', 'Rotate after review', 'Condition values not evaluated']) assert.ok(detailsHtml.includes(expected), expected);
assert.ok(detailsHtml.includes('<th scope="col">'));
assert.deepEqual([...context.investigationEvidence(detailed).kinds], ['policy']);
assert.equal(context.evidenceLabel('unrecognized_value'), 'unrecognized value');

// Unclassified permissions remain unknown and survive the hide-read-only filter.
const unclassified = context.classifyPermissions(['read:custom'], null);
assert.deepEqual([...unclassified.unknown], ['read:custom']);
assert.equal(unclassified.risky.length, 0);
assert.equal(context.getAccessMapRiskClass({ identity: {}, groups: [{ permissions: ['read:custom'] }] }), 'unknown');
context.localStorage = { getItem: () => '1' };
context.AM_CRITICAL_KEY = 'test-critical';
assert.deepEqual([...context.applyCriticalFilter({ permissions: ['read:custom'] }, null).permissions], ['read:custom']);
assert.equal(context.summarizeSeverity({ identity: { permissions_by_severity: { read_only: ['known:read'] } }, groups: [{ permissions: ['known:read', 'read:custom'] }] }).unknown, 1);
assert.equal(context.getGraphResources({ identity: identityOnly, groups: identityOnly.groups }).length, 0);

// Explicit detailed inventory is authoritative, including an empty result; old reports retain inventory.
const noDetailedResources = entry({ assessment: { resources: [] } }, { groups: [{ resources: ['project:placeholder'], permissions: [] }] });
assert.equal(context.countResources([noDetailedResources]), 0);
assert.equal(context.investigationResourceGroups(noDetailedResources).length, 0);
assert.equal(context.getGraphResources({ identity: noDetailedResources, groups: noDetailedResources.groups }).length, 0);
const observedInventory = entry({ assessment: { resources: [{ resource_type: 'bucket', name: 'observed-bucket', permissions: [] }] } });
assert.deepEqual([...context.investigationResourceNames(observedInventory)], ['bucket:observed-bucket']);
assert.equal(context.countResources([entry({}, { groups: [{ resources: ['bucket:old-inventory'], permissions: [] }] })]), 1);
assert.equal(context.countResources([entry({ assessment: { resources: 'malformed' } })]), 1);

// Detailed capabilities override legacy classification, preserving sensitive reads and credential creation.
const reclassified = entry({ assessment: { capabilities: [
  { permission: 'secrets:GetSecret', category: 'sensitive_read' },
  { permission: 'identity:CreateToken', category: 'credential_minting' },
  { permission: 'inventory:List', category: 'metadata_read' },
] } }, { permissions_by_severity: { read_only: ['secrets:GetSecret', 'identity:CreateToken', 'inventory:List'] } });
const correctedBuckets = context.investigationPermissionBuckets(reclassified);
assert.deepEqual([...correctedBuckets.risky], ['secrets:GetSecret']);
assert.deepEqual([...correctedBuckets.privilege_escalation], ['identity:CreateToken']);
assert.deepEqual([...correctedBuckets.read_only], ['inventory:List']);
assert.deepEqual([...context.applyCriticalFilter({ permissions: ['secrets:GetSecret', 'identity:CreateToken', 'inventory:List'] }, correctedBuckets).permissions].sort(), ['identity:CreateToken', 'secrets:GetSecret']);
assert.equal(context.entryHasCritical({ identity: reclassified, groups: reclassified.groups }), true);

// Detailed rollups count unique capabilities, never duplicate legacy buckets or resource metadata labels.
const duplicateClassification = entry({ assessment: { capabilities: [
  { permission: 'secrets:GetSecret', category: 'sensitive_read' },
  { permission: 'secrets:GetSecret', category: 'sensitive_read' },
  { permission: 'inventory:List', category: 'metadata_read' },
] } }, { groups: [{ resources: ['account:example'], permissions: ['role:reader', 'state:Enabled'] }], permissions_by_severity: { risky: ['obsolete:legacy'], read_only: ['secrets:GetSecret', 'inventory:List'] } });
const detailedRollup = context.summarizeSeverity({ identity: duplicateClassification, groups: duplicateClassification.groups });
assert.equal(detailedRollup.risky, 1);
assert.equal(detailedRollup.read_only, 1);
assert.equal(detailedRollup.unknown, 0);
assert.equal(Object.values(detailedRollup).reduce((sum, value) => sum + value, 0), 2);
assert.deepEqual([...context.investigationPermissionNames(duplicateClassification)].sort(), ['inventory:List', 'secrets:GetSecret']);
assert.equal(context.investigationPermissionBuckets(entry({ assessment: { capabilities: [] } }, { permissions_by_severity: { risky: ['legacy:only'] } })).risky.length, 0);
const demoPath = path.join(__dirname, '../docs/viewer/investigation-demo.json');
if (fs.existsSync(demoPath)) {
  const demo = JSON.parse(fs.readFileSync(demoPath, 'utf8'));
  for (const identity of demo.access_map) {
    const summary = context.summarizeSeverity({ identity, groups: context.investigationResourceGroups(identity) });
    assert.equal(Object.values(summary).reduce((sum, value) => sum + value, 0), context.investigationPermissionNames(identity).length, identity.provider);
  }
  const hf = demo.access_map.find(identity => identity.provider === 'huggingface');
  assert.equal(context.summarizeSeverity({ identity: hf, groups: hf.groups }).risky, 0);
}
const chartCanvas = { attributes: {}, setAttribute(name, value) { this.attributes[name] = value; }, getContext() { return null; } };
context.renderDonutChart(chartCanvas, null, [{ key: 'active', label: 'Active' }, { key: 'inactive', label: 'Inactive' }], { active: 5, inactive: 2 }, 'No validation data yet');
assert.equal(chartCanvas.attributes['aria-label'], '7 findings; Active: 5; Inactive: 2');
context.renderDonutChart(chartCanvas, null, [{ key: 'active', label: 'Active' }], {}, 'No validation data yet');
assert.equal(chartCanvas.attributes['aria-label'], 'No validation data yet');

// Malformed optional detailed records are ignored or rendered safely without breaking native/imported reports.
for (const assessment of [null, [], 'invalid', 7, { capability_risk: { toString: 7 }, capabilities: [null, 7, [], 'text', { permission: 'custom:read', category: { toString: 7 }, scope: { toString: 7 } }], resources: [null, 8, [], {}, { name: 'safe', risk: { toString: 7 }, reason: { toString: 7 } }], risk_notes: [{ toString: 7 }], coverage: { toString: 7 } }]) {
  const malformed = entry({ assessment });
  assert.doesNotThrow(() => context.investigationRisk(malformed));
  assert.doesNotThrow(() => context.investigationResourceNames(malformed));
  assert.doesNotThrow(() => context.investigationPermissionBuckets(malformed));
  assert.doesNotThrow(() => context.investigationEvidenceHtml(malformed));
}
const relationshipInjection = entry({ paths: [{ hops: [{ from: 'A', to: 'B', relationship: malicious }] }] });
assert.ok(!context.investigationEvidenceHtml(relationshipInjection).html.includes(malicious));
assert.equal(context.evidenceLabel('__proto__'), '  proto  ');
assert.deepEqual({ ...context.extractResourceParts('arn:aws:s3:::example') }, { resourceType: '', resourceName: 'arn:aws:s3:::example' });

// Collapsed large identities allocate summary DOM only; keyboard activation builds details once.
const created = [];
const element = tag => {
  const item = { tag, children: [], style: {}, dataset: {}, attributes: {}, handlers: new Map(),
    appendChild(child) { this.children.push(child); return child; }, append(...children) { this.children.push(...children); },
    setAttribute(key, value) { this.attributes[key] = value; }, addEventListener(name, fn) { this.handlers.set(name, fn); },
    querySelector() { return null; }, click() { this.handlers.get('click')?.({}); },
    focus() { context.document.activeElement = this; },
  };
  item.classList = { contains(name) { return (item.className || '').split(' ').includes(name); }, add(name) { item.className = (item.className || '') + ' ' + name; }, remove(name) { item.className = (item.className || '').split(' ').filter(value => value !== name).join(' '); }, toggle(name) { if (this.contains(name)) this.remove(name); else this.add(name); } };
  created.push(item); return item;
};
context.document = { createElement: element };
context.expandedAccessKeys = new Set();
context.localStorage = { getItem: () => null };
context.SEVERITY_BUCKETS = [{ key: 'admin', cls: 'admin' }, { key: 'privilege_escalation', cls: 'privesc' }, { key: 'risky', cls: 'risky' }, { key: 'read_only', cls: 'readonly' }, { key: 'unknown', cls: 'unknown' }];
context.syncUrlState = () => {};
const largeIdentity = entry({}, { groups: [{ resources: Array.from({ length: 1000 }, (_, index) => `bucket-${index}`), permissions: Array.from({ length: 4096 }, (_, index) => `permission-${index}`) }] });
context.buildIdentityCard({ key: 'large', identity: largeIdentity, groups: largeIdentity.groups });
assert.ok(created.length < 75, `Collapsed identity allocated ${created.length} elements`);
assert.ok(!created.some(item => item.className === 'evidence-workspace'));
created.length = 0;
const smallIdentity = entry();
context.buildIdentityCard({ key: 'small', identity: smallIdentity, groups: smallIdentity.groups });
const identityHeader = created.find(item => item.className === 'id-card__header');
identityHeader.handlers.get('keydown')({ key: 'Enter', preventDefault() {} });
assert.equal(identityHeader.attributes['aria-expanded'], 'true');
assert.equal(created.filter(item => item.className === 'evidence-workspace').length, 1);
identityHeader.click(); identityHeader.click();
assert.equal(created.filter(item => item.className === 'evidence-workspace').length, 1);
created.length = 0;
context.buildProviderSection('aws', []);
const providerHeader = created.find(item => item.className === 'am-provider-header');
assert.equal(providerHeader.tag, 'button');
assert.equal(providerHeader.handlers.has('keydown'), false, 'Native button keyboard activation must not be duplicated');

// Workspace queue rows use innerHTML too: report-controlled names, paths and
// validation labels must remain escaped, while the action retains the record.
const queue = element('div');
const body = element('body');
context.document.body = body;
context.document.getElementById = id => id === 'investigation-queue' ? queue : null;
context.findings = [{ rule: { name: malicious }, finding: { path: malicious, validation: { status: malicious }, fingerprint: 'untrusted' } }];
context.accessMap = [];
let investigated;
const showFindingDetail = context.showFindingDetail;
context.showFindingDetail = record => { investigated = record; };
context.renderInvestigationWorkspace();
assert.equal(queue.children.length, 1);
assert.ok(queue.children[0].innerHTML.includes('&lt;img'));
assert.ok(!queue.children[0].innerHTML.includes(malicious));
queue.children[0].children[0].click();
assert.equal(investigated, context.findings[0]);

// Exercise the real queue action, including closing back to the overview action.
context.showFindingDetail = showFindingDetail;
const detailElements = new Map();
context.document.getElementById = id => {
  if (id === 'investigation-queue') return queue;
  if (!detailElements.has(id)) detailElements.set(id, element('div'));
  return detailElements.get(id);
};
context.fdPathInput = element('textarea');
context.modalReturnFocus = null;
context.findings = [{ rule: { id: 'example', name: 'Example credential' }, finding: { path: 'example.txt', snippet: 'example', fingerprint: 'example' } }];
queue.children.length = 0;
context.renderInvestigationWorkspace();
const investigateButton = queue.children[0].children[0];
const detailModal = context.document.getElementById('finding-detail');
detailModal.classList.add('hidden');
investigateButton.focus();
investigateButton.click();
assert.equal(detailModal.classList.contains('hidden'), false);
assert.equal(detailModal.attributes['aria-hidden'], 'false');
assert.equal(context.document.getElementById('finding-detail-title').textContent, 'Example credential');
assert.equal(body.classList.contains('modal-open'), true);
assert.equal(context.document.activeElement, context.document.getElementById('finding-detail-close'));
context.closeFindingDetail();
assert.equal(detailModal.classList.contains('hidden'), true);
assert.equal(detailModal.attributes['aria-hidden'], 'true');
assert.equal(body.classList.contains('modal-open'), false);
assert.equal(context.document.activeElement, investigateButton);

// Evidence details are the default; explicit map links and filter state remain accepted.
context.viewRegistry = { 'view-dashboard': {} };
context.window = { location: { search: '' } };
assert.equal(context.readUrlState().accessView, 'details');
context.window.location.search = '?access-view=map&access-provider=aws&access-evidence=conditional';
assert.equal(context.readUrlState().accessView, 'map');
assert.equal(context.readUrlState().accessProvider, 'aws');
assert.equal(context.readUrlState().accessEvidence, 'conditional');
context.window.location.search = '?access-evidence=untrusted';
assert.equal(context.readUrlState().accessEvidence, 'all');

// First load follows the OS; an explicit preference still takes precedence.
context.THEME_KEY = 'test-theme';
context.systemThemeQuery = { matches: true };
context.localStorage = { getItem: () => null };
assert.equal(context.getPreferredTheme(), 'light');
context.systemThemeQuery.matches = false;
assert.equal(context.getPreferredTheme(), 'dark');
context.localStorage = { getItem: key => key === 'test-theme' ? 'light' : null };
assert.equal(context.getPreferredTheme(), 'light');

// The shell starts as a workspace, with compact import rather than a blocking landing page.
assert.match(html, /<body class="workspace-empty">/);
assert.match(html, /<div id="dashboard">/);
assert.match(html, /id="open-report"/);
assert.match(html, /id="investigation-queue"/);
assert.ok(!html.includes('<h2>Load Report</h2>'));
assert.equal((html.match(/fetch\(/g) || []).length, 1, 'Only the existing local report load may use the network');
// Local autoload remains read-only and handles an absent endpoint without blocking the workspace.
(async () => {
  const requests = [];
  context.loaderText = {};
  context.loader = element('div');
  context.fetch = async (url, options) => { requests.push({ url, options }); return { status: 404 }; };
  await context.loadCliReport();
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, '/report');
  assert.equal(requests[0].options.cache, 'no-store');
  let loaded;
  context.parseAndRender = value => { loaded = value; };
  context.fetch = async () => ({ status: 200, ok: true, text: async () => '{"findings":[]}' });
  await context.loadCliReport();
  assert.equal(loaded, '{"findings":[]}');
  console.log('Viewer investigation risk, scope, provenance, confidence, pagination, memory, keyboard, local loading, and workspace regressions passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
