import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { checkDTO } from './system-backup-d-dto-check.mjs';
const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const go = read('backend/internal/systembackupcontract/types.go');
const ts = read('frontend/src/types/systemBackupContract.ts');
test('every existing D Admin object has matching nested wire types', () => {
  const report = checkDTO();
  assert.equal(report.dto_count, 51);
  assert.equal(report.field_count, 444);
  assert.equal(report.contract_frozen, false);
  assert.ok(report.missing_contracts.includes('status_relay'));
});
test('Go nullable, primitive, numeric and nested type changes fail', () => {
  for (const [before, after] of [
    ['*string `json:"retry_of_public_id"`', 'string `json:"retry_of_public_id"`'],
    ['bool    `json:"can_cancel"`', 'string  `json:"can_cancel"`'],
    ['int64   `json:"config_version"`', 'float64 `json:"config_version"`'],
    ['[]Task  `json:"items"`', '[]Operation `json:"items"`'],
    ['[]string `json:"requested_parts"`', 'string `json:"requested_parts"`'],
  ]) {
    assert.ok(go.includes(before), `test mutation missing ${before}`);
    assert.throws(() => checkDTO({ goSource: go.replace(before, after) }), /mismatch/);
  }
});
test('TS open enums, nullability, optional fields and nested collections fail', () => {
  for (const [before, after] of [
    ['retry_of_public_id: string | null;', 'retry_of_public_id: string;'],
    ['task_type: TaskType;', 'task_type: string;'],
    ['can_cancel: boolean;', 'can_cancel?: boolean;'],
    ['items: SystemBackupTask[];', 'items: SystemBackupOperation[];'],
    ['eligibility_reason_codes: EligibilityReasonCode[];', 'eligibility_reason_codes: string[];'],
    ['task_purpose: "acceptance" | "functional_test";', 'task_purpose: string;'],
    ['preflight_mode: "production_readonly" | "functional_test";', 'preflight_mode: string;'],
  ]) {
    assert.ok(ts.includes(before));
    assert.throws(() => checkDTO({ tsSource: ts.replace(before, after) }));
  }
});
test('new objects, wrong contract version and missing referenced schema fail', () => {
  const path = 'contracts/system-backup/v12/admin-task-detail-resources.schema.json';
  for (const mutate of [
    doc => { doc.$defs.NewResource = { type: 'object', additionalProperties: false, properties: {} }; },
    doc => { doc['x-contract-version'] = 'unexpected'; },
    doc => { doc.$defs.BackupDetailResource.properties.task.allOf[0].$ref = 'missing.schema.json#/$defs/Task'; },
  ]) {
    const doc = JSON.parse(read(path)); mutate(doc);
    assert.throws(() => checkDTO({ read: name => name === path ? JSON.stringify(doc) : read(name) }));
  }
});
