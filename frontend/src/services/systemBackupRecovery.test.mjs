import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import ts from 'typescript';

function load(file, overrides, cache = new Map()) {
  if (cache.has(file)) return cache.get(file);
  const exports = {}; cache.set(file, exports);
  runInNewContext(ts.transpileModule(readFileSync(file, 'utf8'), { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText,
    { exports, URLSearchParams, DOMException, require: name => name in overrides ? overrides[name] : load(resolve(dirname(file), name.endsWith('.ts') ? name : `${name}.ts`), overrides, cache) });
  return exports;
}
const id = 'sbk_12345678-1234-4234-8234-123456789abc';
const selection = { kind: 'backups', public_id: id, origin_installation_id: 'installation_test', row_version: 2 };
const key = 'same-reconcile-request-001';
const instant = '2026-10-30T08:00:00Z';
const operation = () => ({
  schema_version: 'system-backup-operation.v1', public_id: 'sop_12345678-1234-4234-8234-123456789abc',
  origin_installation_id: selection.origin_installation_id, operation_type: 'capture_reconcile', target_type: 'backup', target_public_id: id,
  actor_type: 'admin', actor_id: '42', endpoint: 'reconcileSystemBackup', idempotency_key: key, request_hash: 'a'.repeat(64),
  result_resource_public_id: null, result_config_version: null, status: 'succeeded', retryable: false, failure_category: 'none', failure_message: null,
  http_status: 202, row_version: 1, deadline_at: '2026-10-30T08:01:00Z', created_at: instant, updated_at: instant, started_at: instant, finished_at: instant,
});
const setup = transport => load(fileURLToPath(new URL('./systemBackupRecovery.ts', import.meta.url)), { './api': transport });

test('reconciliation repeats the same key and accepts scheduling only on the original operation', async () => {
  const calls = []; const lost = new Error('response lost');
  const api = setup({ post: async (...args) => { calls.push(args); if (calls.length === 1) throw lost; return { status: 202, headers: { 'x-system-backup-data-source': 'live' }, data: operation() }; } });
  const signal = new AbortController().signal;
  await assert.rejects(api.reconcileOriginalBackup(selection, key, signal), err => err === lost);
  assert.equal((await api.reconcileOriginalBackup(selection, key, signal)).status, 'succeeded');
  for (const [path, body, options] of calls) {
    assert.equal(path, `/admin/system-backups/${id}/reconcile`); assert.equal(JSON.stringify(body), '{}'); assert.equal(options.headers['Idempotency-Key'], key);
  }
});
test('unrelated, pending or fixture operations cannot acknowledge reconciliation', async () => {
  for (const mutate of [r => r.data.target_public_id = id.replace('12345678', '87654321'), r => r.data.status = 'pending', r => r.data.operation_type = 'cancel', r => r.headers['x-system-backup-data-source'] = 'fixture']) {
    const response = { status: 202, headers: { 'x-system-backup-data-source': 'live' }, data: operation() }; mutate(response);
    await assert.rejects(setup({ post: async () => response }).reconcileOriginalBackup(selection, key, new AbortController().signal), /unconfirmed_response/);
  }
});
test('capability must match current target and refuse contradictory terminal actions', async () => {
  const base = { schema_version: 'system-backup-recovery-actions.v1', ...selection, status: 'capturing', can_reconcile: true, reason: 'original_recovery_only' };
  const api = capability => setup({ get: async () => ({ status: 200, headers: { 'x-system-backup-data-source': 'live' }, data: capability }) });
  assert.equal((await api(base).readRecoveryActions(selection, new AbortController().signal)).can_reconcile, true);
  for (const a of [{ ...base, status: 'canceled' }, { ...base, row_version: 1 }, { ...base, origin_installation_id: 'installation_other' }]) {
    await assert.rejects(api(a).readRecoveryActions(selection, new AbortController().signal), /unconfirmed_response/);
  }
});

test('lookup-only reconciliation cannot be turned into a new scheduling request', async () => {
  const calls = [];
  const api = setup({ post: async (...args) => { calls.push(args); return { status: 202, headers: { 'x-system-backup-data-source': 'live' }, data: operation() }; } });
  await api.reconcileOriginalBackup(selection, key, new AbortController().signal, true);
  assert.equal(JSON.stringify(calls[0][1]), '{"lookup_only":true}');
  assert.equal(calls[0][2].headers['Idempotency-Key'], key);
});
