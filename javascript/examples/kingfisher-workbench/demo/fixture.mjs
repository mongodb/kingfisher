// Deterministic, local Git fixtures. No caller repository is reset or modified;
// callers provide an already-created private temporary directory.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { TOKEN, RETIRED_TOKEN } from './mock-provider.mjs';

export async function createFixture(directory, mockUrl) {
  const repository = path.join(directory, 'repository');
  const empty = path.join(directory, 'empty-git-config');
  const hooks = path.join(directory, 'empty-hooks');
  await mkdir(repository);
  await mkdir(hooks);
  await writeFile(empty, '', { mode: 0o600 });
  // Isolate inherited Git config/environment, signing, templates and hooks. All
  // timestamps include zones and set BOTH author and committer dates. Windows
  // environment names are case-insensitive; mixed-case GIT_DIR must not leak.
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toUpperCase().startsWith('GIT_')));
  Object.assign(env, {
    GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: empty, GIT_CONFIG_SYSTEM: empty,
    GIT_TERMINAL_PROMPT: '0', GIT_AUTHOR_NAME: 'Kingfisher Demo', GIT_AUTHOR_EMAIL: 'demo@example.invalid',
    GIT_COMMITTER_NAME: 'Kingfisher Demo', GIT_COMMITTER_EMAIL: 'demo@example.invalid',
  });
  function git(args, date) {
    const result = spawnSync('git', ['-C', repository, '-c', `core.hooksPath=${hooks}`, '-c', 'commit.gpgsign=false', '-c', 'core.autocrlf=false', ...args], {
      encoding: 'utf8', env: { ...env, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date },
    });
    if (result.error) throw new Error('Git is required only to create the synthetic demo fixture', { cause: result.error });
    if (result.status !== 0) throw new Error(`Synthetic git ${args[0]} failed: ${result.stderr}`);
    return result.stdout.trim();
  }
  git(['init', '-q', '-b', 'main', `--template=${hooks}`], '2024-10-01T09:00:00Z');
  const current = await readFile(new URL('./fixture/config.env', import.meta.url), 'utf8');
  const config = path.join(repository, 'config.env');
  await writeFile(config, current.replace(TOKEN, RETIRED_TOKEN));
  git(['add', 'config.env'], '2024-10-01T09:00:00Z');
  git(['commit', '-qm', 'add synthetic Acme integration'], '2024-10-01T09:00:00Z');
  const oldCommit = git(['rev-parse', 'HEAD'], '2024-10-01T09:00:00Z');
  await writeFile(config, current);
  git(['add', 'config.env'], '2025-02-14T16:30:00Z');
  git(['commit', '-qm', 'rotate synthetic Acme token'], '2025-02-14T16:30:00Z');
  const newCommit = git(['rev-parse', 'HEAD'], '2025-02-14T16:30:00Z');
  const template = await readFile(new URL('./acme-rule.yml', import.meta.url), 'utf8');
  const rules = path.join(directory, 'acme-rule.yml');
  // Only a loopback address assigned by our own listener can enter the rule.
  if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(mockUrl)) throw new Error('Demo rule requires the local mock origin');
  await writeFile(rules, template.replaceAll('http://127.0.0.1:0', mockUrl), { mode: 0o600 });
  return { repository, rules, oldCommit, newCommit };
}
