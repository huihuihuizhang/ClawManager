import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const exports = {};
runInNewContext(ts.transpileModule(readFileSync(new URL('./backupRecoveryState.ts', import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText, { exports });
const { hasProtectedRecovery } = exports;
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
