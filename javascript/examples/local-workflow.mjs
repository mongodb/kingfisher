// Run: node examples/local-workflow.mjs [--confirm-demo-revoke]
// HTTP is restricted to a newly created 127.0.0.1 server. No real credentials,
// provider APIs, or remote mutations are involved. The flag changes in-memory demo state.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Rules, Scanner, Validator, Revoker } from '../index.mjs';

const args = process.argv.slice(2);
if (args.some(arg => arg !== '--confirm-demo-revoke')) throw new Error('Only --confirm-demo-revoke is supported');
const token = 'acme_demo_a9B2c7D4e1F8g3H6';
const requests = { validation: 0, revocation: 0 };
let active = true;
const server = createServer((request, response) => {
  if (request.headers.authorization !== `Bearer ${token}`) { response.writeHead(401).end(); return; }
  if (request.method === 'GET' && request.url === '/identity') {
    requests.validation += 1;
    response.writeHead(active ? 200 : 401, { 'Content-Type': 'application/json' });
    response.end(JSON.stringify({ authenticated: active }));
  } else if (request.method === 'POST' && request.url === '/revoke') {
    requests.revocation += 1;
    active = false;
    response.writeHead(204).end();
  } else response.writeHead(404).end();
});
let directory, scanner, validator, revoker;
try {
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const url = `http://127.0.0.1:${server.address().port}`;
  directory = await mkdtemp(path.join(process.env.KINGFISHER_TEST_TMPDIR ?? tmpdir(), 'kingfisher-node-demo-'));
  const rulesPath = path.join(directory, 'demo.yml');
  await writeFile(rulesPath, `rules:
  - id: acme.example-token
    name: Acme example token
    confidence: high
    pattern: '\\b(acme_demo_[A-Za-z0-9]{16})\\b'
    min_entropy: 0
    examples:
      - ${token}
    validation:
      type: Http
      content:
        request:
          method: GET
          url: '${url}/identity'
          headers:
            Authorization: 'Bearer {{ TOKEN }}'
          response_matcher:
            - type: StatusMatch
              status: [200]
            - type: WordMatch
              words: ['"authenticated":true']
    revocation:
      type: Http
      content:
        request:
          method: POST
          url: '${url}/revoke'
          headers:
            Authorization: 'Bearer {{ TOKEN }}'
          response_matcher:
            - type: StatusMatch
              status: [204]
`, { mode: 0o600 });
  const rules = await Rules.load({
    paths: [rulesPath], builtins: false, cache: false,
    confidence: 'high', includeDependencies: true,
  });
  scanner = await Scanner.create({ rules });
  // Only for this loopback demo. Leave allowInternalIps:false in real integrations
  // unless access to specific internal credential destinations is explicitly authorized.
  validator = new Validator({ allowInternalIps: true, httpFallbacks: false, concurrency: 2, retries: 0 });
  revoker = await Revoker.create({ rules });
  const source = `ACME_TOKEN=${token}\n`;

  const findings = await scanner.scan(source, { path: 'demo.env' });
  const diagnostics = await validator.inspect(findings); // Offline prerequisites, not liveness.
  const plan = await revoker.prepare(source, { path: 'demo.env' }); // Also offline.
  assert.deepEqual(requests, { validation: 0, revocation: 0 });
  console.log(JSON.stringify({ phase: 'prepared', plan: plan.toJSON(), diagnostics }));

  // validate() may send credentials; here only the synthetic local server receives them.
  // Select only original high-confidence findings; retain the full batch for helpers.
  const candidates = findings.filter(finding => finding.visible && finding.confidence === 'high');
  const results = await validator.validate(findings, { candidates, timeoutMs: 5000 });
  assert.equal(results.length, 1);
  assert.equal(results[0].outcome, 'verified_active');
  assert.equal(results[0].revocationReady, true);
  console.log(JSON.stringify({ phase: 'validated', results: results.map(r => r.toJSON()) }));

  if (args.includes('--confirm-demo-revoke')) {
    // Retain this original result in memory. A saved JSON report or redacted()
    // copy does not preserve the private action inputs needed for revocation.
    const result = await revoker.revoke(results[0], { confirm: true, timeoutMs: 5000 });
    assert.equal(result.revoked, true);
    assert.equal(requests.revocation, 1);
    console.log(JSON.stringify({ phase: 'revoked', result }));
  }
  console.log(JSON.stringify({ phase: 'summary', requests, active }));
} finally {
  const closed = await Promise.allSettled([scanner?.close(), validator?.close(), revoker?.close()]);
  server.closeAllConnections();
  if (server.listening) await new Promise(resolve => server.close(resolve));
  if (directory) await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  const failure = closed.find(result => result.status === 'rejected');
  if (failure) throw failure.reason;
}
