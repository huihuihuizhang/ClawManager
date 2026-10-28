import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

function load(file, overrides = {}, cache = new Map()) {
  if (cache.has(file)) return cache.get(file);
  const exports = {};
  cache.set(file, exports);
  const source = ts.transpileModule(readFileSync(file, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
  }).outputText;
  runInNewContext(source, { exports, URLSearchParams, DOMException, require: name => {
    if (name in overrides) return overrides[name];
    assert.ok(name.startsWith('.'), `unexpected dependency ${name}`);
    return load(resolve(dirname(file), name.endsWith('.ts') ? name : `${name}.ts`), overrides, cache);
  } });
  return exports;
}
const id = 'sbk_12345678-1234-4234-8234-123456789abc';
const selection = { kind: 'backups', public_id: id, origin_installation_id: 'installation_test', row_version: 1 };
const key = 'same-cancel-key-0001';
function operation() {
  const instant = '2026-10-28T08:00:00Z';
  return {
    schema_version: 'system-backup-operation.v1', public_id: 'sop_12345678-1234-4234-8234-123456789abc',
    origin_installation_id: selection.origin_installation_id, operation_type: 'cancel', target_type: 'backup', target_public_id: id,
    actor_type: 'admin', actor_id: '42', endpoint: 'cancelSystemBackup', idempotency_key: key, request_hash: 'a'.repeat(64),
    result_resource_public_id: null, result_config_version: null, status: 'succeeded', retryable: false,
    failure_category: 'none', failure_message: null, http_status: 202, row_version: 1,
    deadline_at: '2026-10-28T08:01:00Z', created_at: instant, updated_at: instant, started_at: instant, finished_at: instant,
  };
}
function setup(post) {
  return load(fileURLToPath(new URL('./systemBackupActions.ts', import.meta.url)), { './api': { post } });
}

test('cancel retries retain the caller key and accept only the persisted operation', async () => {
  const calls = [];
  const error = new Error('response lost');
  const { cancelUnstartedBackup } = setup(async (...args) => {
    calls.push(args);
    if (calls.length === 1) throw error;
    return { status: 202, headers: { 'x-system-backup-data-source': 'live' }, data: operation() };
  });
  const signal = new AbortController().signal;
  await assert.rejects(cancelUnstartedBackup(selection, key, signal), e => e === error);
  assert.equal((await cancelUnstartedBackup(selection, key, signal)).public_id, operation().public_id);
  assert.equal(calls.length, 2);
  for (const [path, body, options] of calls) {
    assert.equal(path, `/admin/system-backups/${id}/cancel`);
    assert.equal(JSON.stringify(body), '{}');
    assert.equal(options.headers['Idempotency-Key'], key);
    assert.equal(options.signal, signal);
  }
});

test('unrelated, fixture, incomplete or unconfirmed cancellation cannot show success', async () => {
  for (const mutation of [
    r => { r.headers['x-system-backup-data-source'] = 'fixture'; },
    r => { r.status = 200; },
    r => { r.data.origin_installation_id = 'installation_other'; },
    r => { r.data.idempotency_key = 'different-request-key'; },
    r => { r.data.target_public_id = id.replace('12345678', '87654321'); },
    r => { r.data.status = 'pending'; },
    r => { r.data.secret = 'must-not-be-exposed'; },
  ]) {
    const response = { status: 202, headers: { 'x-system-backup-data-source': 'live' }, data: operation() };
    mutation(response);
    const api = setup(async () => response);
    await assert.rejects(api.cancelUnstartedBackup(selection, key, new AbortController().signal), /unconfirmed_response/);
  }
});

test('unsupported or malformed targets do not issue requests', async () => {
  let calls = 0;
  const api = setup(async () => { calls++; });
  for (const target of [{ ...selection, kind: 'drills' }, { ...selection, public_id: '../another' }]) {
    await assert.rejects(api.cancelUnstartedBackup(target, key, new AbortController().signal), /invalid_target/);
  }
  assert.equal(calls, 0);
});

test('active cancellation is accepted as pending, never represented as completed', async () => {
  const pending = { ...operation(), status: 'pending', http_status: null, started_at: null, finished_at: null };
  const api = setup(async () => ({status: 202, headers: {'x-system-backup-data-source': 'live'}, data: pending}));
  const result = await api.cancelUnstartedBackup(selection, key, new AbortController().signal);
  assert.equal(result.status, 'pending');
  assert.equal(result.finished_at, null);
});
