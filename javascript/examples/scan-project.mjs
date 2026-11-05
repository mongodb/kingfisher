// Run: node examples/scan-project.mjs [one-or-more-local-paths]
// Offline detection only. stdout is redacted JSONL; errors go to stderr.
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { Rules, Scanner, filesystem, expandArchives, expandContent } from '../index.mjs';

const roots = process.argv.slice(2);
const teaching = roots.length === 0;
if (teaching) roots.push(fileURLToPath(new URL('./fixtures/project', import.meta.url)));
// Only the no-argument synthetic fixture uses a teaching rule. User-supplied
// projects always receive the complete built-in catalog, not a demo detector.
const rules = await Rules.load(teaching ? {
  paths: [fileURLToPath(new URL('./fixtures/acme-token.yml', import.meta.url))],
  builtins: false, cache: false,
} : {});
const scanner = await Scanner.create({ rules, maxInputBytes: 16 * 1024 * 1024 });
const controller = new AbortController();
const interrupt = () => controller.abort();
process.on('SIGINT', interrupt);

try {
  // Enumeration, decompression, extraction and detection are separate stages.
  // Pass the same signal to every stage; each timeout has its documented scope.
  const controls = { signal: controller.signal, timeoutMs: 60_000 };
  const files = filesystem(roots, {
    ...controls, gitignore: true, hidden: false,
    onWarning(warning) {
      // Continue readable roots, but never report incomplete coverage as clean.
      // Structured JSON safely escapes control characters in caller paths.
      console.error(JSON.stringify({ warning: warning.reason, path: warning.path }));
      process.exitCode = 1;
    },
  });
  const members = expandArchives(files, { ...controls, depth: 2, maxBytes: 16 * 1024 * 1024, maxEntries: 1000 });
  const content = expandContent(members, { ...controls, sqlite: true, pyc: true, pdf: false, maxBytes: 16 * 1024 * 1024 });
  for await (const result of scanner.scanInputs(content, controls)) {
    // Includes the input path, extraction diagnostics and every finding.
    // Do not discard invisible helpers before any later same-input validation.
    if (!process.stdout.write(JSON.stringify(result.toJSON()) + '\n')) await once(process.stdout, 'drain');
  }
} catch (error) {
  // Never replace a failed scan with [] or a "no secrets" report. A stream can
  // contain earlier completed inputs before a later input fails; exit nonzero.
  console.error(JSON.stringify({ error: error.name, code: error.code ?? null, message: error.message }));
  process.exitCode = 1;
} finally {
  process.removeListener('SIGINT', interrupt);
  await scanner.close();
}
