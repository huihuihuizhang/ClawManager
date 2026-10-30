import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const root = new URL('../', import.meta.url);
const text = path => readFileSync(new URL(path, root), 'utf8');
const json = path => JSON.parse(text(path));

test('new operation preserves enum ordinals and matches both language contracts', () => {
  const types = json('contracts/system-backup/v12/status-failure-enums.schema.json').$defs.OperationType.enum;
  const migration = text('backend/internal/db/migrations/130_backup_v2_capture_reconcile.sql');
  const enums = [...migration.match(/ENUM\(([^)]*)\)/)[1].matchAll(/'([^']+)'/g)].map(match => match[1]);
  assert.deepEqual(enums, types);
  assert.equal(types.at(-1), 'capture_reconcile');
  assert.equal(types.at(-2), 'evidence_download_admission');
  for (const path of ['backend/internal/systembackupcontract/types.go', 'frontend/src/types/systemBackupContract.ts']) assert.ok(text(path).includes('"evidence_download_admission", "capture_reconcile"'));
  assert.ok(migration.includes('sbv2_chk_capture_reconcile'));
});

test('the declared live routes have separate read and operate authority and closed requests', () => {
  const contract = json('contracts/system-backup/team-integration.openapi.json');
  const read = contract.paths['/admin/system-backups/{backup_public_id}/recovery-actions'].get;
  const write = contract.paths['/admin/system-backups/{backup_public_id}/reconcile'].post;
  assert.deepEqual(read['x-required-permissions'], ['system_backup.read']);
  assert.deepEqual(write['x-required-permissions'], ['system_backup.operate']);
  assert.equal(write.requestBody.content['application/json'].schema.additionalProperties, false);
  assert.deepEqual(Object.keys(write.requestBody.content['application/json'].schema.properties), ['lookup_only']);
  for (const op of [read, write]) assert.ok(op.responses.default);
  assert.equal(contract.$defs.RecoveryActions.additionalProperties, false);
});
