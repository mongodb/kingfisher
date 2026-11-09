import { homedir } from 'node:os';
import path from 'node:path';

const MiB = 1024 ** 2;
export const HELP = `Kingfisher Workbench — native Node SDK secret-scanning showcase

Usage: npm start -- <directory> [options]

Reports (offline and redacted by default):
  --root <directory>       Same as positional directory
  --out <file>             HTML snapshot (default: ./report.html)
  --json <file>            Also export the same report entries as JSON
  --audit <new-file>       Live revocation audit; refuses any existing path
                          Requires --validate --enable-revoke without --no-serve
                          Default: per-session revocations-<id>.jsonl beside HTML
  --port <n>               Loopback report port (default: 0 = free port)
  --open                   Open the live report in your browser
  --no-serve               Write a non-operational static snapshot and exit
  --show-secrets           Explicitly export RAW credentials/captures/messages
  --redact                 Restore default credential redaction
  --quiet, -q              Suppress progress, not the final report URL
  --no-progress            Disable TTY progress

Detection and enumeration (never execute input files):
  --jobs, -j <n>           In-flight inputs, 1–32 (default: 4)
  --confidence, -c <level> low|medium|high (default: medium)
  --no-dedup               Keep every occurrence (default: one per rule + secret)
  --rules <path>           Additional trusted YAML/TOML rules file or directory
  --no-builtins           Load only --rules (used by the synthetic demo)
  --max-file-size <size>   File/blob/per-input cap (default: 64MiB; 0 = unlimited)
  --exclude <text>         Skip root-relative paths containing text (repeatable)
  --include-ignored       Scan files ignored by .gitignore (default: respect it)
  --exclude-hidden        Skip dotfiles (default: include .env and other dotfiles)
  --no-extract            Skip archive/SQLite/bytecode/PDF transforms
  --extraction-depth <n>  Archive depth, 0–8 (default: 2)
  --max-extracted-size <size>  Per-source extraction budget (default: 64MiB)
  --no-git-history        Scan working tree only (default: all refs if root has .git)
  --git-history-max-commits <n>  Fail if history exceeds budget (default: 100000)
  --git-history-max-inputs <n>   Fail if versions exceed budget (default: 1000000)
                          Set either history budget to 0 for unlimited; not truncation

Explicit provider operations:
  --validate              Send credentials to rule-defined providers for live checks
  --enable-revoke         Arm one-shot UI/API revocation; REQUIRES --validate
  --no-validate           Disable live checks (default); cannot arm revocation
  --no-revoke             Disable revocation (default)
  --concurrency <n>       Validation concurrency, 1–32 (default: 4)
  --timeout <ms>          Per validation/revocation operation (default: 10000)
  --allow-internal-ips    Allow private destinations in TRUSTED validation rules
  --help, -h              Show help

The server binds only to 127.0.0.1. Static snapshots contain no session token.
Revocation also requires an active native validation snapshot and confirmation.
Even redacted reports contain paths, commit metadata and fingerprints: review
before sharing. Use npm run demo for an entirely loopback synthetic example.`;

function integer(value, name, min, max = Number.MAX_SAFE_INTEGER) {
  if (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) < min || Number(value) > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return Number(value);
}
function size(value, name, unlimited = true) {
  if (unlimited && value === '0') return null;
  const match = /^(\d+(?:\.\d+)?)\s*(b|kib|kb|mib|mb|gib|gb)?$/i.exec(value);
  const units = { b: 1, kb: 1000, kib: 1024, mb: 1000 ** 2, mib: MiB, gb: 1000 ** 3, gib: 1024 ** 3 };
  const bytes = match && Math.floor(Number(match[1]) * units[(match[2] ?? 'b').toLowerCase()]);
  if (!Number.isSafeInteger(bytes) || bytes < 1) throw new Error(`${name} must be a positive byte count such as 64MiB${unlimited ? ', or 0' : ''}`);
  return bytes;
}
function absolute(value) {
  return path.resolve(value === '~' ? homedir() : value.startsWith('~/') ? path.join(homedir(), value.slice(2)) : value);
}

export function parseArgs(argv) {
  const options = {
    root: null, out: 'report.html', json: null, audit: null, port: 0, open: false, serve: true,
    quiet: false, progress: undefined, maxFileSize: 64 * MiB, maxExtractedSize: 64 * MiB,
    concurrency: 4, jobs: 4, timeoutMs: 10_000, confidence: 'medium', dedup: true,
    extract: true, extractionDepth: 2, rules: null, builtins: true, exclude: [],
    gitHistory: true, gitHistoryMaxCommits: 100_000, gitHistoryMaxInputs: 1_000_000,
    gitignore: true, hidden: true, validate: false, revoke: false, redact: true,
    allowInternalIps: false,
  };
  // Null prototypes keep positional names such as "constructor" out of the
  // option tables, including when a caller extends Object.prototype.
  const flags = { __proto__: null,
    '--open': ['open', true], '--no-serve': ['serve', false], '--quiet': ['quiet', true], '-q': ['quiet', true],
    '--no-progress': ['progress', false], '--no-dedup': ['dedup', false], '--no-extract': ['extract', false],
    '--no-git-history': ['gitHistory', false], '--include-ignored': ['gitignore', false],
    '--exclude-hidden': ['hidden', false], '--validate': ['validate', true], '--no-validate': ['validate', false],
    '--enable-revoke': ['revoke', true], '--no-revoke': ['revoke', false], '--redact': ['redact', true],
    '--show-secrets': ['redact', false], '--allow-internal-ips': ['allowInternalIps', true],
    '--no-builtins': ['builtins', false], '--help': ['help', true], '-h': ['help', true],
  };
  const strings = { __proto__: null, '--root': 'root', '--out': 'out', '--json': 'json', '--audit': 'audit', '--rules': 'rules' };
  const numbers = { __proto__: null,
    '--port': ['port', 0, 65_535], '--jobs': ['jobs', 1, 32], '-j': ['jobs', 1, 32],
    '--concurrency': ['concurrency', 1, 32], '--timeout': ['timeoutMs', 1, 600_000],
    '--extraction-depth': ['extractionDepth', 0, 8],
    '--git-history-max-commits': ['gitHistoryMaxCommits', 0], '--git-history-max-inputs': ['gitHistoryMaxInputs', 0],
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') {
      if (options.root || argv.length !== index + 2) throw new Error('Exactly one directory must follow --');
      options.root = argv[++index];
      continue;
    }
    const equal = arg.indexOf('=');
    const name = equal < 0 ? arg : arg.slice(0, equal);
    if (flags[name]) {
      if (equal >= 0) throw new Error(`${name} takes no value`);
      const [key, value] = flags[name];
      options[key] = value;
      continue;
    }
    if (!name.startsWith('-')) {
      if (options.root) throw new Error(`Unexpected directory: ${arg}`);
      options.root = arg;
      continue;
    }
    if (!strings[name] && !numbers[name] && !['--confidence', '-c', '--exclude', '--max-file-size', '--max-extracted-size'].includes(name)) {
      throw new Error(`Unknown option: ${name}`);
    }
    const value = equal < 0 ? argv[++index] : arg.slice(equal + 1);
    if (!value || value.startsWith('-')) throw new Error(`Missing value for ${name}`);
    if (strings[name]) {
      if (name === '--root' && options.root) throw new Error('Select one directory: positional or --root, not both');
      options[strings[name]] = value;
    }
    else if (numbers[name]) {
      const [key, min, max] = numbers[name];
      options[key] = integer(value, name, min, max);
    } else if (name === '--exclude') options.exclude.push(value);
    else if (name === '--confidence' || name === '-c') {
      if (!['low', 'medium', 'high'].includes(value)) throw new Error('Confidence must be low, medium, or high');
      options.confidence = value;
    } else if (name === '--max-file-size') options.maxFileSize = size(value, name);
    else options.maxExtractedSize = size(value, name, false);
  }
  // Do not silently broaden authority: a mistaken flag combination is an error,
  // not permission to validate or to mutate. Order only matters for paired flags.
  if (options.revoke && !options.validate) throw new Error('--enable-revoke requires explicit --validate');
  if (!options.builtins && !options.rules) throw new Error('--no-builtins requires --rules');
  // Only a live, revoke-enabled server writes an audit; never silently ignore the path.
  if (options.audit && (!options.revoke || !options.serve)) throw new Error('--audit requires a live session with --validate --enable-revoke');
  for (const key of ['root', 'out', 'json', 'audit', 'rules']) if (options[key]) options[key] = absolute(options[key]);
  return options;
}
