'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const { inspect } = require('node:util');
const { Rules, Scanner, Validator, Revoker, AbortError, TimeoutError } = require('../index.cjs');
const { TOKEN, temporary, rulesIn, server, httpRule } = require('./helpers.cjs');

test('validation is explicit, classifies reliable evidence, and omits provider bodies', async () => {
  const directory = temporary();
  const inactive = 'kf_b8C1d6E3f0G7h2I5';
  const unavailable = 'kf_c7D0e5F2g9H6i1J4';
  const throttled = 'kf_d6E9f4G1h8I5j0K3';
  let requests = 0;
  const mock = await server((request, response) => {
    requests++;
    const credential = request.headers.authorization;
    response.setHeader('Content-Type', 'application/json');
    if (credential === `Bearer ${TOKEN}`) response.end(JSON.stringify({ authenticated: true, privateEcho: TOKEN }));
    else if (credential === `Bearer ${inactive}`) { response.statusCode = 401; response.end('{}'); }
    else if (credential === `Bearer ${throttled}`) { response.statusCode = 429; response.end('{}'); }
    else response.end('{"unrelated":true}');
  });
  let scanner;
  const validator = new Validator({ allowInternalIps: true });
  try {
    const rules = await rulesIn(directory, httpRule(mock.url));
    scanner = await Scanner.create({ rules });
    const findings = await scanner.scan([TOKEN, inactive, unavailable, throttled].join('\n'));
    assert.equal(requests, 0);
    const results = await validator.validate(findings);
    const byToken = new Map(results.map(result => [result.finding.secret, result]));
    assert.equal(byToken.get(TOKEN).outcome, 'verified_active');
    assert.equal(byToken.get(inactive).outcome, 'verified_inactive');
    assert.equal(byToken.get(unavailable).outcome, 'unavailable');
    assert.equal(byToken.get(throttled).outcome, 'unavailable');
    assert.equal(requests, 4);
    assert.ok(!JSON.stringify(results).includes(TOKEN));
    assert.ok(!JSON.stringify(results).includes('privateEcho'));
    assert.ok(!inspect(results, { depth: 10 }).includes(TOKEN));
    assert.equal(byToken.get(TOKEN).credential().secret, '[REDACTED]');
    assert.equal(byToken.get(TOKEN).credential({ redact: false }).secret, TOKEN);
  } finally {
    await scanner?.close(); await validator.close(); await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('revocation requires confirmation and the original active credential snapshot', async () => {
  const directory = temporary();
  let mutations = 0;
  const mock = await server((request, response) => {
    if (request.url === '/identity') response.end('{"authenticated":true}');
    else { mutations++; response.statusCode = 204; response.end(); }
  });
  let scanner;
  let revoker;
  const validator = new Validator({ allowInternalIps: true });
  try {
    const rules = await rulesIn(directory, httpRule(mock.url));
    scanner = await Scanner.create({ rules });
    revoker = await Revoker.create({ rules });
    const [result] = await validator.validate(await scanner.scan(TOKEN));
    assert.equal(result.revocationReady, true);
    assert.equal(mutations, 0);
    await assert.rejects(revoker.revoke(result), TypeError);
    await assert.rejects(revoker.revoke(result.toJSON(), { confirm: true }), TypeError);
    await assert.rejects(revoker.revoke(result.redacted(), { confirm: true }), TypeError);
    await assert.rejects(revoker.revokeSecret('acme.node-token', TOKEN, { confirm: true,
      variables: { VALIDATION_URL: `${mock.url}/other` } }), TypeError);
    assert.equal(mutations, 0);
    assert.equal((await revoker.revoke(result, { confirm: true })).revoked, true);
    assert.equal(mutations, 1);
  } finally {
    await scanner?.close(); await revoker?.close(); await validator.close(); await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('batch revocation deduplicates exact action snapshots and does not replace their rules', async () => {
  const directory = temporary();
  let checks = 0;
  let originalMutations = 0;
  let replacementMutations = 0;
  const original = await server((request, response) => {
    if (request.url === '/identity') { checks++; response.end('{"authenticated":true}'); }
    else { originalMutations++; response.statusCode = 204; response.end(); }
  });
  const replacement = await server((_, response) => { replacementMutations++; response.statusCode = 204; response.end(); });
  let scanner;
  let revoker;
  const validator = new Validator({ allowInternalIps: true });
  try {
    const rules = await rulesIn(directory, httpRule(original.url));
    scanner = await Scanner.create({ rules });
    const results = await validator.validate(await scanner.scan(`${TOKEN}\n${TOKEN}`));
    assert.equal(checks, 1);
    const changed = await rulesIn(directory, httpRule(replacement.url), 'acme.node-token', 'replacement.yml');
    revoker = await Revoker.create({ rules: changed });
    const outcomes = await revoker.revokeMany(results, { confirm: true });
    assert.deepEqual(outcomes.map(result => result.outcome), ['revoked', 'duplicate']);
    assert.equal(outcomes[1].duplicateOf, 0);
    assert.equal(originalMutations, 1);
    assert.equal(replacementMutations, 0);
  } finally {
    await scanner?.close(); await revoker?.close(); await validator.close();
    await original.close(); await replacement.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('revocation preparation is offline and validates only explicitly selected candidates', async () => {
  const directory = temporary();
  let checks = 0;
  let mutations = 0;
  const mock = await server((request, response) => {
    if (request.url === '/identity') { checks++; response.end('{"authenticated":true}'); }
    else { mutations++; response.statusCode = 204; response.end(); }
  });
  let revoker;
  const validator = new Validator({ allowInternalIps: true });
  try {
    const rules = await rulesIn(directory, httpRule(mock.url));
    revoker = await Revoker.create({ rules });
    const plan = await revoker.prepare(`token=${TOKEN}`, { provider: 'acme', path: 'upload.env' });
    assert.equal(checks, 0);
    assert.equal(mutations, 0);
    assert.equal(plan.candidates.length, 1);
    assert.equal(plan.sourcePath, 'upload.env');
    assert.ok(!JSON.stringify(plan).includes(TOKEN));
    const [result] = await plan.validate(validator);
    assert.equal(result.outcome, 'verified_active');
    assert.equal(checks, 1);
    assert.equal(mutations, 0);
    const file = path.join(directory, 'token.env');
    fs.writeFileSync(file, TOKEN);
    assert.equal((await revoker.prepareFromFile(file, { provider: 'acme' })).candidates.length, 1);
    assert.equal(checks, 1);
  } finally {
    await revoker?.close(); await validator.close(); await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('plan variables retain the supplied validator work limit and close cancellation', async () => {
  const directory = temporary();
  let started;
  const submitted = new Promise(resolve => { started = resolve; });
  let checks = 0;
  const mock = await server(request => {
    checks++;
    assert.equal(request.headers['x-scope'], 'approved-tenant');
    started(); // Keep the response pending until validator.close() cancels it.
  });
  let revoker;
  const validator = new Validator({ allowInternalIps: true, maxPendingOperations: 1 });
  try {
    const extra = httpRule(mock.url).replace("Authorization: 'Bearer {{ TOKEN }}'",
      "Authorization: 'Bearer {{ TOKEN }}'\n            X-Scope: '{{ SCOPE }}'");
    const rules = await rulesIn(directory, extra);
    revoker = await Revoker.create({ rules });
    const plan = await revoker.prepare(TOKEN, { variables: { SCOPE: 'approved-tenant' } });
    const pending = plan.validate(validator);
    pending.catch(() => {});
    await submitted;
    await assert.rejects(plan.validate(validator), error => error.code === 'ERR_KINGFISHER_BUSY');
    await validator.close();
    await assert.rejects(pending, AbortError);
    assert.equal(checks, 1);
  } finally {
    await revoker?.close(); await validator.close(); await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('HTTP fallbacks are opt-in and revocation never fails over the selected action', async () => {
  const directory = temporary();
  let primaryChecks = 0;
  let primaryMutations = 0;
  let secondaryChecks = 0;
  let secondaryMutations = 0;
  const primary = await server((request, response) => {
    if (request.url === '/identity') { primaryChecks++; response.statusCode = 401; }
    else { primaryMutations++; response.statusCode = 204; }
    response.end();
  });
  const secondary = await server((request, response) => {
    if (request.url === '/identity') { secondaryChecks++; response.end('{"authenticated":true}'); }
    else { secondaryMutations++; response.statusCode = 503; response.end(); }
  });
  let scanner;
  let revoker;
  const primaryOnly = new Validator({ allowInternalIps: true });
  const fallbacks = new Validator({ allowInternalIps: true, httpFallbacks: true });
  try {
    const extra = httpRule(primary.url) + `    fallbacks:
      - id: secondary
        reuse_primary_validation_logic: true
        url: '${secondary.url}/identity'
        reuse_primary_revocation_logic: true
        revocation_url: '${secondary.url}/revoke'
`;
    const rules = await rulesIn(directory, extra);
    scanner = await Scanner.create({ rules });
    revoker = await Revoker.create({ rules });
    const findings = await scanner.scan(TOKEN);
    assert.equal((await primaryOnly.validate(findings))[0].outcome, 'verified_inactive');
    assert.equal(primaryChecks, 1);
    assert.equal(secondaryChecks, 0);
    const [result] = await fallbacks.validate(findings);
    assert.equal(result.outcome, 'verified_active');
    assert.equal(result.revocationReady, true);
    assert.equal(secondaryChecks, 1);
    await assert.rejects(revoker.revoke(result, { confirm: true }),
      error => error.code === 'ERR_KINGFISHER_REVOCATION_UNKNOWN' && error.outcomeUnknown);
    assert.equal(secondaryMutations, 1);
    assert.equal(primaryMutations, 0);
    assert.equal(primaryChecks, 2); // Result-based revocation did not revalidate.
    assert.equal((await revoker.revokeSecret('acme.node-token', TOKEN, { confirm: true })).revoked, true);
    assert.equal(primaryMutations, 1); // Direct revocation retains primary behavior.
    assert.equal(secondaryMutations, 1);
    assert.equal(primaryChecks, 2);
  } finally {
    await scanner?.close(); await revoker?.close(); await primaryOnly.close(); await fallbacks.close();
    await primary.close(); await secondary.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('cancellation after mutation submission is unknown and never automatically retried', async () => {
  const directory = temporary();
  const controller = new AbortController();
  let mutations = 0;
  const mock = await server((request, response) => {
    if (request.url === '/identity') response.end('{"authenticated":true}');
    else { mutations++; controller.abort(); /* Deliberately never confirm the submitted action. */ }
  });
  let scanner;
  let revoker;
  const validator = new Validator({ allowInternalIps: true });
  try {
    const rules = await rulesIn(directory, httpRule(mock.url));
    scanner = await Scanner.create({ rules });
    revoker = await Revoker.create({ rules });
    const [result] = await validator.validate(await scanner.scan(TOKEN));
    await assert.rejects(revoker.revoke(result, { confirm: true, signal: controller.signal }),
      error => error instanceof AbortError && error.outcomeUnknown === true);
    assert.equal(mutations, 1);
  } finally {
    await scanner?.close(); await revoker?.close(); await validator.close(); await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('a validation batch deadline cancels pending orchestration without partial results', async () => {
  const directory = temporary();
  const mock = await server(() => {});
  let scanner;
  const validator = new Validator({ allowInternalIps: true });
  try {
    const rules = await rulesIn(directory, httpRule(mock.url));
    scanner = await Scanner.create({ rules });
    await assert.rejects(validator.validate(await scanner.scan(TOKEN), { timeoutMs: 30 }), TimeoutError);
  } finally {
    await scanner?.close(); await validator.close(); await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('invisible credential helpers stay with the input through validation', async () => {
  const directory = temporary();
  let checks = 0;
  const mock = await server((request, response) => {
    checks++;
    assert.equal(request.headers['x-user'], 'user_a9B2c7D4');
    response.end('{"authenticated":true}');
  });
  let scanner;
  const validator = new Validator({ allowInternalIps: true });
  try {
    const extra = `    depends_on_rule:
      - rule_id: acme.username
        variable: USERNAME
        within: '2L'
${httpRule(mock.url).replace("Authorization: 'Bearer {{ TOKEN }}'", "Authorization: 'Bearer {{ TOKEN }}'\n            X-User: '{{ USERNAME }}'")}
  - id: acme.username
    name: Supporting username
    visible: false
    pattern: 'user=(user_[A-Za-z0-9]{8})'
    min_entropy: 0
`;
    const rules = await rulesIn(directory, extra);
    scanner = await Scanner.create({ rules });
    const findings = await scanner.scan(`user=user_a9B2c7D4\ntoken=${TOKEN}`);
    assert.equal(findings.length, 2);
    const results = await validator.validate(findings);
    assert.equal(results.find(result => result.finding.visible).outcome, 'verified_active');
    assert.equal(checks, 1);
    const missing = await validator.validate(findings.filter(finding => finding.visible));
    assert.equal(missing[0].outcome, 'skipped');
    assert.equal(checks, 1);
  } finally {
    await scanner?.close(); await validator.close(); await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('Betterleaks analysis reuses private validation evidence only on explicit invocation', async () => {
  const directory = temporary();
  let checks = 0;
  const mock = await server((_, response) => { checks++; response.end('{"id":"account-123"}'); });
  let scanner;
  const validator = new Validator({ allowInternalIps: true });
  try {
    const file = path.join(directory, 'analysis.toml');
    fs.writeFileSync(file, `[[rules]]
id = "acme-analysis"
description = "Acme analysis"
regex = '''\\b(kf_[A-Za-z0-9]{16})\\b'''
validate = '''let r = http.get("${mock.url}/identity"); r.status == 200 ? {"result": "valid", "analysis": {"id": r.json.id}} : validate.unknown(r)'''
analyze = '''{"identity": {"id": string(validation.analysis.id)}}'''
`);
    const rules = await Rules.load({ paths: [file], builtins: false, cache: false });
    scanner = await Scanner.create({ rules });
    const [result] = await validator.validate(await scanner.scan(TOKEN));
    assert.equal(result.outcome, 'verified_active');
    assert.equal(checks, 1);
    assert.ok(!JSON.stringify(result).includes('account-123'));
    const analysis = await validator.analyze(result);
    assert.equal(analysis.identity.id, 'account-123');
    assert.equal(checks, 1);
    await assert.rejects(validator.analyze(result.redacted()));
  } finally {
    await scanner?.close(); await validator.close(); await mock.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
