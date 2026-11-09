import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { link, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { assertDistinctOutputs } from '../src/safety.mjs';

async function directory(t) {
  const owned = await mkdtemp(path.join(tmpdir(), 'kingfisher-workbench-output-test-'));
  // Remove only this exact private directory, never either caller-selected output.
  t.after(() => rm(owned, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  return owned;
}
const collision = { code: 'ERR_WORKBENCH_OUTPUT_COLLISION' };

test('output identities reject equivalent absolute and relative new paths without writing', async (t) => {
  const root = await directory(t);
  const output = path.join(root, 'report.html');
  await assert.rejects(assertDistinctOutputs([output, path.relative(process.cwd(), output)]), collision);
  await assert.rejects(stat(output), { code: 'ENOENT' });
});

test('output identities resolve linked parents and nested missing directories without creating them', async (t) => {
  const root = await directory(t);
  const actual = path.join(root, 'actual'), alias = path.join(root, 'alias');
  await mkdir(actual);
  // Junctions exercise directory aliases on Windows without symlink privileges.
  await symlink(actual, alias, process.platform === 'win32' ? 'junction' : 'dir');
  for (const suffix of ['report.html', path.join('missing', 'nested', 'report.html')]) {
    await assert.rejects(assertDistinctOutputs([path.join(actual, suffix), path.join(alias, suffix)]), collision);
    await assert.rejects(stat(path.join(actual, suffix)), { code: 'ENOENT' });
  }
  await assert.rejects(stat(path.join(actual, 'missing')), { code: 'ENOENT' });
});

test('output identities reject existing hardlink aliases without changing bytes or permissions', async (t) => {
  const root = await directory(t);
  const output = path.join(root, 'report.html'), alias = path.join(root, 'report.json');
  await writeFile(output, 'prior report\n', { mode: 0o640 });
  await link(output, alias);
  const before = await stat(output);
  await assert.rejects(assertDistinctOutputs([output, alias]), collision);
  for (const file of [output, alias]) {
    assert.equal(await readFile(file, 'utf8'), 'prior report\n');
    assert.equal((await stat(file)).mode, before.mode);
  }
});

test('output identities reject existing file symlink aliases where creation is permitted', async (t) => {
  const root = await directory(t);
  const output = path.join(root, 'report.html'), alias = path.join(root, 'report.json');
  await writeFile(output, 'prior report\n');
  try { await symlink(output, alias, 'file'); }
  catch (error) {
    if (process.platform !== 'win32' || !['EPERM', 'EACCES'].includes(error.code)) throw error;
    t.skip('Windows file symlink creation requires Developer Mode or administrator privileges');
    return;
  }
  await assert.rejects(assertDistinctOutputs([output, alias]), collision);
  assert.equal(await readFile(output, 'utf8'), 'prior report\n');
});

test('new case-only output spellings are conservatively rejected on every filesystem', async (t) => {
  const root = await directory(t);
  for (const [html, json] of [
    ['report.html', 'REPORT.HTML'],
    [path.join('Missing', 'nested', 'report.html'), path.join('missing', 'NESTED', 'REPORT.HTML')],
  ]) {
    await assert.rejects(assertDistinctOutputs([path.join(root, html), path.join(root, json)]), collision);
    await assert.rejects(stat(path.join(root, html)), { code: 'ENOENT' });
  }
  await assert.rejects(stat(path.join(root, 'Missing')), { code: 'ENOENT' });
});

test('different output names or existing parent identities remain valid without creating files', async (t) => {
  const root = await directory(t);
  const left = path.join(root, 'left'), right = path.join(root, 'right');
  await mkdir(left); await mkdir(right);
  const html = path.join(left, 'report.html'), json = path.join(left, 'report.json');
  await assertDistinctOutputs([html, json, null]);
  await assertDistinctOutputs([html, path.join(right, 'report.html')]);
  await writeFile(html, 'prior report\n');
  await assertDistinctOutputs([html, json]);
  assert.equal(await readFile(html, 'utf8'), 'prior report\n');
  await assert.rejects(stat(json), { code: 'ENOENT' });
});
