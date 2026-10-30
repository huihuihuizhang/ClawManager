import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const exports = {};
runInNewContext(ts.transpileModule(readFileSync(new URL('./backupRecoveryState.ts', import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText, { exports });
const { hasProtectedRecovery, hasSourceGateWait } = exports;
const task = 'sbk_original';
const event = { target_type: 'backup', target_public_id: task, event_type: 'diagnostic.d.recovery_blocked' };
test('only the original active backup diagnostic explains recovery protection', () => {
  assert.equal(hasProtectedRecovery('capturing', task, [event]), true);
  assert.equal(hasProtectedRecovery('canceling', task, [event]), true);
  assert.equal(hasProtectedRecovery('capturing', task, [{ ...event, target_public_id: 'sbk_other' }]), false);
  assert.equal(hasProtectedRecovery('capturing', task, [{ ...event, target_type: 'drill' }]), false);
  assert.equal(hasProtectedRecovery('capturing', task, [{ ...event, event_type: 'diagnostic.d.other' }]), false);
  assert.equal(hasProtectedRecovery('capturing', task, []), false);
});
test('historical blocked recovery does not override later authoritative results', () => {
  for (const status of ['pending', 'validating', 'publishing', 'succeeded', 'failed', 'canceled']) {
    assert.equal(hasProtectedRecovery(status, task, [event]), false);
  }
});

test('source admission wait belongs to the original task and ends when capture advances', () => {
  const waiting = { ...event, event_type: 'diagnostic.d.source_gate_wait' };
  for (const status of ['preparing', 'ready_for_capture', 'acquiring_gate']) assert.equal(hasSourceGateWait(status, task, [waiting]), true);
  for (const status of ['capturing', 'validating', 'succeeded', 'failed', 'canceled']) assert.equal(hasSourceGateWait(status, task, [waiting]), false);
  assert.equal(hasSourceGateWait('preparing', task, [{ ...waiting, target_public_id: 'sbk_other' }]), false);
  assert.equal(hasSourceGateWait('preparing', task, [{ ...waiting, target_type: 'drill' }]), false);
});
