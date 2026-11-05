// Run from javascript/: npm run test:types
// Then (Node 22.13+): node --experimental-strip-types examples/typed-scan.mts
import { fileURLToPath } from 'node:url';
import { Rules, Scanner, ScanInput, type ScanResultReport } from 'kingfisher-secret-scanner';

// Resolve the fixture relative to this example, not the caller's working directory.
const rulesFile = fileURLToPath(new URL('../examples/fixtures/acme-token.yml', import.meta.url));
const rules = await Rules.load({ paths: [rulesFile], builtins: false, cache: false });
const scanner = await Scanner.create({ rules, maxPendingOperations: 2 });
try {
  const input = new ScanInput({ path: 'typed.env', data: 'TOKEN=acme_demo_a9B2c7D4e1F8g3H6\n' });
  const result = await scanner.scanInput(input, { timeoutMs: 5000 });
  const report: ScanResultReport = result.toJSON();
  console.log(JSON.stringify(report));
} finally { await scanner.close(); }
