'use strict';

// Native integration tests: custom rules and localhost-only mock providers.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { Rules, Scanner, Validator, Revoker, AbortError, TimeoutError } = require('../index.cjs');
const { TOKEN, temporary, ruleYaml, rulesIn, server, httpRule } = require('./helpers.cjs');

const USER = 'user_a9B2c7D4';
const REGION = 'region_a9B2';
const OTHER = 'other_c7D0e5F2';
const SOURCE = `region=${REGION}\nuser=${USER}\ntoken=${TOKEN}\nother=${OTHER}`;

function dependencyRules(url, unrelatedPattern = 'other=(other_[A-Za-z0-9]{8})') {
  return ruleYaml(`    confidence: high
    depends_on_rule:
      - rule_id: acme.username
        variable: USERNAME
        within: '4L'
${httpRule(url).replace("Authorization: 'Bearer {{ TOKEN }}'", "Authorization: 'Bearer {{ TOKEN }}'\n            X-User: '{{ USERNAME }}'")}
  - id: acme.username
    name: Visible low confidence username helper
    confidence: low
    visible: true
    pattern: 'user=(user_[A-Za-z0-9]{8})'
    min_entropy: 0
    depends_on_rule:
      - rule_id: acme.region
        variable: REGION
        within: '4L'
${httpRule(`${url}/helper`)}
  - id: acme.region
    name: Hidden transitive region helper
    confidence: low
    visible: false
    pattern: 'region=(region_[A-Za-z0-9]{4})'
    min_entropy: 0
  - id: acme.unrelated
    name: Unrelated low confidence HTTP credential
    confidence: low
    pattern: '${unrelatedPattern}'
    min_entropy: 0
${httpRule(`${url}/unrelated`)}`, 'acme.primary');
}

async function dependencyFixture(t, options = {}, handler) {
  const directory = temporary();
  const requests = [];
  const mock = await server((request, response) => {
    requests.push({ url: request.url, authorization: request.headers.authorization, user: request.headers['x-user'] });
    if (handler) handler(request, response);
    else response.end('{"authenticated":true}');
  });
  const file = path.join(directory, 'rules.yml');
  fs.writeFileSync(file, dependencyRules(mock.url));
  const resources = [];
  t.after(async () => {
    await Promise.all(resources.map(resource => resource.close()));
    await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const rules = await Rules.load({ paths: [file], builtins: false, cache: false, confidence: 'low', ...options });
  const scanner = await Scanner.create({ rules });
  const validator = new Validator({ allowInternalIps: true });
  resources.push(scanner, validator);
  const findings = await scanner.scan(SOURCE);
  return { directory, file, mock, requests, rules, scanner, validator, findings, resources };
}

test('native candidates bind low helpers without checking them or unrelated providers', async t => {
  const { findings, validator, requests } = await dependencyFixture(t);
  assert.equal(findings.length, 4);
  const primary = findings.find(finding => finding.ruleId === 'acme.primary');
  const helper = findings.find(finding => finding.ruleId === 'acme.username');
  const unrelated = findings.find(finding => finding.ruleId === 'acme.unrelated');
  assert.equal(helper.visible, true);
  assert.equal(helper.confidence, 'low');
  assert.equal(requests.length, 0); // Detection remains offline.

  const [result] = await validator.validate(findings, { candidates: [primary] });
  assert.equal(result.outcome, 'verified_active');
  assert.equal(result.finding.ruleId, 'acme.primary');
  assert.equal(result.credential({ redact: false }).variables.USERNAME, USER);
  assert.deepEqual(requests, [{ url: '/identity', authorization: `Bearer ${TOKEN}`, user: USER }]);
  assert.equal(JSON.stringify(result).includes(TOKEN), false);
  assert.equal(JSON.stringify(result).includes(USER), false);
  assert.deepEqual(await validator.validate(findings, { candidates: [] }), []);
  assert.equal(requests.length, 1);

  const missing = await validator.validate([primary], { candidates: [primary] });
  assert.equal(missing[0].outcome, 'skipped');
  assert.equal(requests.length, 1); // Full raw context, not a prefiltered batch, is required.
  const selected = await validator.validate(findings, { candidates: [unrelated, primary] });
  assert.deepEqual(selected.map(value => value.finding.ruleId), ['acme.unrelated', 'acme.primary']);
  assert.deepEqual(requests.slice(1).map(request => request.url).sort(), ['/identity', '/unrelated/identity']);

  const defaults = await validator.validate(findings);
  assert.equal(defaults.length, 4); // Omission retains the existing complete-batch behavior.
  assert.equal(requests.length, 6);
  assert.equal(requests.filter(request => request.url === '/helper/identity').length, 1);
});

test('native includeDependencies retains visible and hidden transitive helpers before compile', async t => {
  const { findings, rules, validator, requests } = await dependencyFixture(t, {
    confidence: 'high', includeDependencies: true,
  });
  assert.deepEqual(rules.metadata().map(rule => rule.id).sort(), ['acme.primary', 'acme.region', 'acme.username']);
  assert.deepEqual(findings.map(finding => finding.ruleId).sort(), ['acme.primary', 'acme.region', 'acme.username']);
  assert.equal(findings.find(finding => finding.ruleId === 'acme.region').visible, false);
  const candidates = findings.filter(finding => finding.confidence === 'high' && finding.visible);
  const [result] = await validator.validate(findings, { candidates });
  assert.equal(result.outcome, 'verified_active');
  assert.deepEqual(requests.map(request => request.url), ['/identity']);
});

test('native dependency retention is opt-in and unrelated low regexes are not compiled', async t => {
  const { file, mock, rules, findings, validator, requests } = await dependencyFixture(t, { confidence: 'high' });
  assert.equal(rules.length, 1);
  // Existing detection drops a required within-window dependency when its
  // helper rule was not loaded. The default loader must not silently expand it.
  assert.deepEqual(findings, []);
  assert.deepEqual(await validator.validate(findings), []);
  assert.equal(requests.length, 0);

  // A deliberately invalid low-only detector proves exclusion happens before
  // native regex compilation, rather than filtering metadata/findings afterward.
  fs.writeFileSync(file, dependencyRules(mock.url, '('));
  const selected = await Rules.load({ paths: [file], builtins: false, cache: false,
    confidence: 'high', includeDependencies: true });
  assert.deepEqual(selected.metadata().map(rule => rule.id).sort(), ['acme.primary', 'acme.region', 'acme.username']);
  await assert.rejects(Rules.load({ paths: [file], builtins: false, cache: false,
    confidence: 'low', includeDependencies: true }), error => error.code === 'ERR_KINGFISHER_RULES');
});

test('native builtin dependency retention still excludes the unrelated low generic API key', async () => {
  const rules = await Rules.load({ confidence: 'medium', includeDependencies: true, cache: false });
  const ids = new Set(rules.metadata().map(rule => rule.id));
  assert.equal(ids.has('betterleaks.generic-api-key'), false);
  assert.equal(ids.has('betterleaks.generic-password'), false);
  assert.equal(ids.has('betterleaks.generic-username'), false);
  assert.equal(ids.has('betterleaks.generic-credential-uri'), true);
  assert.equal(rules.detail('betterleaks.generic-credential-uri').confidence, 'medium');
});

test('native dependency retention supports unchanged mixed YAML and namespaced Betterleaks TOML', async () => {
  const directory = temporary();
  let scanner;
  try {
    const primary = path.join(directory, 'primary.yml');
    const helper = path.join(directory, 'helpers.toml');
    fs.writeFileSync(primary, ruleYaml(`    confidence: high
    depends_on_rule:
      - rule_id: custom.acme-helper
        variable: HELPER
        within: '2L'
`, 'acme.primary'));
    fs.writeFileSync(helper, `[[rules]]
id = "acme-helper"
description = "Low helper"
regex = '(helper_[a-z]{8})'
confidence = "low"
[[rules]]
id = "acme-unrelated"
description = "Unrelated low detector"
regex = '(other_[a-z]{8})'
confidence = "low"
`);
    const rules = await Rules.load({ paths: [primary, helper], builtins: false, cache: false,
      confidence: 'high', includeDependencies: true });
    assert.deepEqual(rules.metadata().map(rule => rule.id).sort(), ['acme.primary', 'custom.acme-helper']);
    scanner = await Scanner.create({ rules });
    const findings = await scanner.scan(`helper_abcdefgh\n${TOKEN}\nother_abcdefgh`);
    assert.deepEqual(findings.map(finding => finding.ruleId).sort(), ['acme.primary', 'custom.acme-helper']);
  } finally {
    await scanner?.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('native dependency closure follows final custom overrides and handles cycles and missing IDs', async () => {
  const directory = temporary();
  try {
    const first = path.join(directory, 'first.yml');
    const override = path.join(directory, 'override.yml');
    fs.writeFileSync(first, ruleYaml(`    confidence: high
    depends_on_rule:
      - rule_id: acme.old-helper
        variable: OLD
  - id: acme.old-helper
    name: Old helper
    confidence: low
    pattern: '(old_[a-z]{8})'
    min_entropy: 0
`, 'acme.primary'));
    fs.writeFileSync(override, ruleYaml(`    confidence: high
    depends_on_rule:
      - rule_id: acme.new-helper
        variable: NEW
      - rule_id: acme.missing
        variable: MISSING
  - id: acme.new-helper
    name: New helper
    confidence: low
    pattern: '(new_[a-z]{8})'
    min_entropy: 0
    depends_on_rule:
      - rule_id: acme.cycle
        variable: CYCLE
  - id: acme.cycle
    name: Cyclic helper
    confidence: low
    pattern: '(cycle_[a-z]{8})'
    min_entropy: 0
    depends_on_rule:
      - rule_id: acme.new-helper
        variable: NEW
`, 'acme.primary'));
    const rules = await Rules.load({ paths: [first, override], builtins: false, cache: false,
      confidence: 'high', includeDependencies: true });
    assert.deepEqual(rules.metadata().map(rule => rule.id).sort(), ['acme.cycle', 'acme.new-helper', 'acme.primary']);
    assert.equal(rules.detail('acme.primary').depends_on_rule[0].rule_id, 'acme.new-helper');
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});

test('native candidate membership rejects mixed original input contexts before requests', async t => {
  const { findings, scanner, validator, requests } = await dependencyFixture(t);
  const foreign = await scanner.scan(SOURCE);
  await assert.rejects(validator.validate(findings, { candidates: [foreign[0]] }), /members/);
  const mixed = [findings[0], foreign[0]];
  await assert.rejects(validator.validate(mixed, { candidates: [mixed[0]] }), TypeError);
  assert.equal(requests.length, 0);
});

test('native selected checks keep cancellation, causes, deadlines and no-partial-results semantics', async t => {
  const controller = new AbortController();
  const reason = new Error('stop selected checks');
  const { findings, validator, requests } = await dependencyFixture(t, {}, () => {
    controller.abort(reason); // Leave the selected localhost response pending.
  });
  const candidates = findings.filter(finding => finding.ruleId === 'acme.primary');
  await assert.rejects(validator.validate(findings, { candidates, signal: controller.signal }),
    error => error instanceof AbortError && error.code === 'ERR_KINGFISHER_CANCELLED' && error.cause === reason);
  assert.deepEqual(requests.map(request => request.url), ['/identity']);
  await assert.rejects(validator.validate(findings, { candidates: [], signal: controller.signal }), AbortError);
  const timedOut = validator.validate(findings, { candidates, timeoutMs: 30 });
  await assert.rejects(timedOut, error => error instanceof TimeoutError && error.code === 'ERR_KINGFISHER_TIMEOUT');
  assert.equal(requests.every(request => request.url === '/identity'), true);
});

test('native selected validation retains fallback and credential snapshots for result revocation', async () => {
  const directory = temporary();
  const requests = [];
  const primary = await server((request, response) => {
    requests.push(['primary', request.url, request.headers.authorization]);
    response.statusCode = 401;
    response.end();
  });
  const secondary = await server((request, response) => {
    requests.push(['secondary', request.url, request.headers.authorization]);
    if (request.url === '/identity') response.end('{"authenticated":true}');
    else { response.statusCode = 204; response.end(); }
  });
  let scanner;
  let revoker;
  const validator = new Validator({ allowInternalIps: true, httpFallbacks: true });
  try {
    const rules = await rulesIn(directory, httpRule(primary.url) + `    fallbacks:
      - id: secondary
        reuse_primary_validation_logic: true
        url: '${secondary.url}/identity'
        reuse_primary_revocation_logic: true
        revocation_url: '${secondary.url}/revoke'
`);
    scanner = await Scanner.create({ rules });
    revoker = await Revoker.create({ rules });
    const findings = await scanner.scan(`${TOKEN}\nkf_b8C1d6E3f0G7h2I5`);
    const candidates = [findings.find(finding => finding.secret === TOKEN)];
    const [result] = await validator.validate(findings, { candidates });
    assert.equal(result.outcome, 'verified_active');
    assert.equal(result.revocationReady, true);
    const report = result.toObject({ redact: false });
    report.finding.secret = 'caller-modified-report';
    const credential = result.credential({ redact: false });
    credential.secret = 'caller-modified-credential';
    credential.variables.VALIDATION_URL = `${primary.url}/identity`;
    credential.variables.VALIDATION_REVOCATION_URL = `${primary.url}/revoke`;
    candidates.length = 0;
    findings.length = 0;
    assert.equal((await revoker.revoke(result, { confirm: true })).revoked, true);
    assert.deepEqual(requests, [
      ['primary', '/identity', `Bearer ${TOKEN}`],
      ['secondary', '/identity', `Bearer ${TOKEN}`],
      ['secondary', '/revoke', `Bearer ${TOKEN}`],
    ]); // No unselected token, revalidation, primary mutation, or mutation failover.
  } finally {
    await scanner?.close(); await revoker?.close(); await validator.close();
    await primary.close(); await secondary.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('native candidates use preflight semantics for incomplete template inputs', async t => {
  const directory = temporary();
  const requests = [];
  const mock = await server((request, response) => {
    requests.push(request.url);
    response.end('{"authenticated":true}');
  });
  const file = path.join(directory, 'rules.yml');
  // EXTRA is neither a capture, a dependency, nor a validator variable.
  fs.writeFileSync(file, ruleYaml(httpRule(mock.url).replace(
    "Authorization: 'Bearer {{ TOKEN }}'",
    "Authorization: 'Bearer {{ TOKEN }}'\n            X-Extra: '{{ EXTRA }}'",
  )));
  const rules = await Rules.load({ paths: [file], builtins: false, cache: false });
  const scanner = await Scanner.create({ rules });
  const validator = new Validator({ allowInternalIps: true });
  t.after(async () => {
    await Promise.all([scanner.close(), validator.close()]);
    await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  const findings = await scanner.scan(`token=${TOKEN}`);
  assert.equal(findings.length, 1);

  // Whole-batch validation renders the missing variable as empty and still checks it.
  const [batch] = await validator.validate(findings);
  assert.equal(batch.outcome, 'verified_active');
  assert.equal(requests.length, 1);

  // Selected candidates are preflighted like RevocationPlan.validate(): incomplete
  // inputs are skipped before any provider request.
  const [selected] = await validator.validate(findings, { candidates: findings });
  assert.equal(selected.outcome, 'skipped');
  assert.equal(selected.reason, 'missing_dependency');
  assert.equal(requests.length, 1);
});
