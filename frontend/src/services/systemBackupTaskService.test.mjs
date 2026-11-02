import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

function compiled(path, require) {
  const exports = {};
  runInNewContext(ts.transpileModule(readFileSync(new URL(path, import.meta.url), 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  }).outputText, { exports, require, TextEncoder });
  return exports;
}

// Use the real closed task-response validator; only the authenticated HTTP
// transport is replaced. This CONTENT fixture grants no execution authority.
const types = compiled('../types/systemBackupContract.ts', name => { throw new Error(name); });
const validator = compiled('../pages/admin/backups/backupApiRead.ts', name => {
  if (name.endsWith('systemBackupContract.ts')) return types;
  throw new Error(name);
});
function service(post) {
  return compiled('./systemBackupTaskService.ts', name => {
    if (name === './api') return { post };
    if (name.endsWith('backupApiRead.ts')) return validator;
    throw new Error(name);
  });
}
const key = 'original-backup-key-20261102';
function response() {
  return { status: 202, headers: { 'x-system-backup-data-source': 'live' }, data: {
    schema_version: 'system-backup-task.v1', public_id: 'sbk_11111111-1111-4111-8111-111111111111',
    origin_installation_id: 'installation_original', task_type: 'backup', actor_type: 'admin', actor_id: '42',
    endpoint: 'createSystemBackup', idempotency_key: key, request_hash: 'a'.repeat(64), request_id: 'original-request-20261102',
    retry_of_public_id: null, status: 'pending', pending_reason: 'none', attention_reason: 'none', can_cancel: true,
    config_version: 1, retryable: false, failure_category: 'none', failure_message: null, heartbeat_at: null,
    row_version: 1, next_reconcile_at: null, deadline_at: '2026-11-03T02:00:00Z', started_at: null,
    finished_at: null, created_at: '2026-11-03T01:00:00Z', updated_at: '2026-11-03T01:00:00Z',
  } };
}

test('complete non-DR backup posts every domain without changing the separate acceptance request', async () => {
  const calls = [], client = service(async (...args) => { calls.push(args); return response(); });
  const signal = new AbortController().signal;
  const result = await client.createSystemBackupTask('backup', client.completeBackupRequestJSON, key, signal);
  assert.equal(result.public_id, response().data.public_id);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '/admin/system-backups');
  assert.equal(calls[0][1], client.completeBackupRequestJSON);
  assert.equal(calls[0][2].headers['Idempotency-Key'], key);
  assert.equal(calls[0][2].headers['Content-Type'], 'application/json');
  assert.equal(calls[0][2].signal, signal);
  const request = JSON.parse(calls[0][1]);
  assert.deepEqual(request, { task_purpose: 'functional_test', requested_parts: ['mysql', 'redis', 'object_storage', 'workspace', 'deployment_resources', 'secret_bundle'] });
  assert.deepEqual(JSON.parse(client.acceptanceBackupRequestJSON), { ...request, task_purpose: 'acceptance' });
});

test('unknown result is not retried automatically; explicit retry retains the exact body and key', async () => {
  const calls = [], client = service(async (...args) => { calls.push(args); if (calls.length === 1) throw new Error('transport_unknown'); return response(); });
  await assert.rejects(client.createSystemBackupTask('backup', client.completeBackupRequestJSON, key), /transport_unknown/);
  assert.equal(calls.length, 1);
  await client.createSystemBackupTask('backup', client.completeBackupRequestJSON, key);
  assert.equal(calls.length, 2);
  assert.equal(calls[0][1], calls[1][1]);
  assert.equal(calls[0][2].headers['Idempotency-Key'], calls[1][2].headers['Idempotency-Key']);
});

test('wrong endpoint, key, schema or non-live response cannot confirm creation', async () => {
  for (const mutate of [r => { r.data.endpoint = 'otherEndpoint'; }, r => { r.data.idempotency_key = 'other-backup-key-20261102'; }, r => { r.data.unknown_field = true; }, r => { r.headers['x-system-backup-data-source'] = 'preview'; }, r => { r.status = 200; }]) {
    const client = service(async () => { const r = response(); mutate(r); return r; });
    await assert.rejects(client.createSystemBackupTask('backup', client.completeBackupRequestJSON, key), /not_ready/);
  }
});
