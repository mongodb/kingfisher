// Rule loading, policy selection and operation controls remain independently usable.
import { Rules, DetectionScanner, DetectionPolicy, CancellationToken, AbortError } from '../index.mjs';

const rules = await Rules.load({ paths: process.argv.slice(2), cache: true });
console.log({ rules: rules.length, cacheStatus: rules.cacheStatus });
console.log(rules.metadata().slice(0, 3)); // Capability names, not credentials.

const scanner = await DetectionScanner.create({ rules, policy: new DetectionPolicy() });
try {
  const cancellation = new CancellationToken();
  cancellation.cancel();
  try {
    await scanner.scan('ordinary configuration', { cancellation, timeoutMs: 1_000 });
  } catch (error) {
    if (!(error instanceof AbortError)) throw error;
    console.log({ cancelled: true }); // A failed call is not an empty successful scan.
  }
  const results = await scanner.scan('ordinary configuration', { path: 'config.env' });
  console.log(results.filter(finding => finding.visible)); // Default inspection is redacted.
} finally {
  await scanner.close();
}
