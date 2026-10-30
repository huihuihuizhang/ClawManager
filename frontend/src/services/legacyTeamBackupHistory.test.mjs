import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const id = 'sbk_' + 'a'.repeat(32);
const job = { public_id: id, operation: 'backup', status: 'running', phase: 'capture_mysql', created_at: '2026-10-30T00:00:00Z', requires_inspection: true };
const page = { items: [job], unfinished_count: 1, history_only: true, writes_available: false };
function load(get) {
  const exports = {};
  runInNewContext(ts.transpileModule(readFileSync(new URL('./legacyTeamBackupHistory.ts', import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  }).outputText, { exports, require: name => { assert.equal(name, './api'); return { get }; } });
  return exports;
}

test('legacy history uses GET only, preserves unfinished status and follows the server cursor', async () => {
  const calls = [];
  const api = load(async (...args) => { calls.push(args); return { status: 200, data: { success: true, data: page } }; });
  assert.equal((await api.listLegacyTeamBackupHistory(id)).items[0].status, 'running');
  assert.equal(calls[0][0], '/admin/system-backup/team-data/jobs');
  assert.equal(calls[0][1].params.before, id);
  await assert.rejects(api.listLegacyTeamBackupHistory('../escape'), /validation_failed/);
  assert.equal(calls.length, 1);
});

test('missing capability, unknown response and permission failure cannot become empty successful history', async () => {
  for (const mutation of [p => delete p.history_only, p => p.writes_available = true, p => delete p.items[0].requires_inspection, p => p.unfinished_count = -1]) {
    const data = structuredClone(page); mutation(data);
    await assert.rejects(load(async () => ({ status: 200, data: { success: true, data } })).listLegacyTeamBackupHistory(), /unconfirmed_response/);
  }
  const denied = new Error('permission_denied');
  await assert.rejects(load(async () => { throw denied; }).listLegacyTeamBackupHistory(), err => err === denied);
});

test('details must belong to the requested operation and remain read-only', async () => {
  const api = load(async () => ({ status: 200, data: { success: true, history_only: true, writes_available: false, data: job } }));
  assert.equal((await api.getLegacyTeamBackupHistory(id)).requires_inspection, true);
  await assert.rejects(api.getLegacyTeamBackupHistory('sbk_' + 'b'.repeat(32)), /unconfirmed_response/);
});
