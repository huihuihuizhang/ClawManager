// Local contract/reordering DATA only. Not a real backend or backup proof.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { acceptedTask, advanceDetail, parts } from './backup-live-contract.mjs';
const key = 'local-contract-key-12345';
const task = { schema_version: 'system-backup-task.v1', task_type: 'backup',
  public_id: 'sbk_11111111-2222-3333-4444-555555555555', origin_installation_id: 'installation_local',
  endpoint: 'createSystemBackup', idempotency_key: key, row_version: 1, status: 'pending' };
const headers = { 'x-system-backup-data-source': 'live', location: `/api/v1/admin/system-backups/${task.public_id}` };
const accepted = acceptedTask(202, headers, task, key);
const detail = (rv, status = 'succeeded') => ({ schema_version: 'system-backup-backup-detail.v1', task: { ...task, row_version: rv, status },
  task_purpose: 'acceptance', requested_parts: parts, artifact_state: 'committed', artifact_usable: true,
  acceptance_ready: true, acceptance_eligible: true, consistency: 'strong', verifier_summary: { aggregate_status: 'passed' },
  checksums: Object.fromEntries(['manifest','index','marker','acceptance','catalog'].map(k => [k, 'a'.repeat(64)])) });
const detailHeaders = rv => ({ ...headers, 'x-system-backup-origin-installation-id': task.origin_installation_id,
  'x-system-backup-task-row-version': String(rv) });
test('Create bare projected DTO, live marker, endpoint/key and Location contract', () => {
  assert.equal(accepted.public_id, task.public_id);
  for (const [status, h, value, k] of [[200, headers, task, key], [202, {}, task, key],
    [202, headers, {data: task}, key], [202, headers, {...task, endpoint:'wrong'}, key],
    [202, headers, task, 'other-key'], [202, {...headers,location:'/wrong'}, task, key]]) {
    assert.throws(() => acceptedTask(status, h, value, k));
  }
});
test('Out-of-order and equal-version responses cannot overwrite newer ready or failed snapshots', () => {
  const ready = advanceDetail(null, accepted, detailHeaders(10), detail(10));
  assert.equal(ready.ready, true);
  assert.equal(advanceDetail(ready, accepted, detailHeaders(9), detail(9, 'capturing')), ready);
  assert.equal(advanceDetail(ready, accepted, detailHeaders(10), detail(10, 'capturing')), ready);
  const failed = advanceDetail(ready, accepted, detailHeaders(11), detail(11, 'failed'));
  assert.equal(failed.status, 'failed'); assert.equal(failed.ready, false);
  assert.equal(advanceDetail(failed, accepted, detailHeaders(10), detail(10)), failed);
});
test('Detail identity, origin and exact header/body row version must match', () => {
  assert.throws(() => advanceDetail(null, accepted, detailHeaders(2), {...detail(2), task:{...task,row_version:2,public_id:'foreign'}}));
  assert.throws(() => advanceDetail(null, accepted, {...detailHeaders(2),'x-system-backup-origin-installation-id':'installation_other'}, detail(2)));
  assert.throws(() => advanceDetail(null, accepted, detailHeaders(3), detail(2)));
});
test('202/request parts alone and missing catalog checksum never qualify as public artifact ready', () => {
  assert.equal(advanceDetail(null, accepted, detailHeaders(2), detail(2,'capturing')).ready, false);
  const data = detail(2); data.checksums.catalog = null;
  assert.equal(advanceDetail(null, accepted, detailHeaders(2), data).ready, false);
});
