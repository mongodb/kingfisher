// Run: node examples/git-scopes.mjs <local-repository> [snapshot|history|diff|staged] [ref] [baseline]
// Read-only: the SDK does not clone, fetch, checkout, or execute a Git subprocess.
import { Rules, Scanner, gitInputs } from '../index.mjs';

const [repository, mode = 'snapshot', ref = 'HEAD', baseline] = process.argv.slice(2);
if (!repository) throw new Error('Pass a local repository path; see examples/README.md');
if (mode === 'diff' && !baseline) throw new Error('diff requires a baseline, for example HEAD~1');
if (mode === 'staged' && (ref !== 'HEAD' || baseline)) throw new Error('staged uses its default HEAD baseline; omit ref/baseline arguments');

// Use all trusted built-ins for real repository scans; acquisition is still offline.
const scanner = await Scanner.create({ rules: await Rules.load() });
let warnings = 0;
try {
  const inputs = gitInputs(repository, {
    mode, refs: [ref], ...(mode === 'diff' ? { sinceCommit: baseline } : {}),
    discover: false, maxCommits: 50_000, maxInputs: 10_000, maxBlobSize: 8 * 1024 * 1024,
    skipMissingBlobs: false,
    onWarning(warning) {
      warnings += 1;
      // A skipped blob is incomplete coverage, never a successful clean input.
      console.error(JSON.stringify({ warning: 'incomplete-git-coverage', ...warning }));
    },
  });
  for await (const result of scanner.scanInputs(inputs, { timeoutMs: 60_000 })) {
    console.log(JSON.stringify(result.toJSON()));
  }
  if (warnings) process.exitCode = 2;
} catch (error) {
  console.error(JSON.stringify({ error: error.name, code: error.code ?? null, message: error.message }));
  process.exitCode = 1;
} finally { await scanner.close(); }
