import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import ts from 'typescript';

const exports = {};
runInNewContext(ts.transpileModule(readFileSync(new URL('./backupCreateSubmission.ts', import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText, { exports });
const { canSubmitCompleteBackup } = exports;
const records = () => ({ kind: 'records', data: {
  origin_installation_id: 'original',
  config: { kind: 'ready', value: { active: true, origin_installation_id: 'original', version: 3, effective_enabled: false } },
  backups: { kind: 'ready', value: { origin_installation_id: null, items: [] } },
} });

test('readable active original config and backup records allow submission without claiming readiness', () => {
  assert.equal(canSubmitCompleteBackup(records()), true);
  const state = records();
  state.data.backups.value = { origin_installation_id: 'original', items: [{ origin_installation_id: 'original' }] };
  assert.equal(canSubmitCompleteBackup(state), true);
});

test('missing reads, inactive config or a different installation cannot enable submission', () => {
  for (const mutate of [
    s => { s.data.config = { kind: 'unavailable' }; },
    s => { s.data.backups = { kind: 'unavailable' }; },
    s => { s.data.config.value.active = false; },
    s => { s.data.origin_installation_id = 'other'; },
    s => { s.data.backups.value.origin_installation_id = 'other'; },
    s => { s.data.backups.value.items = [{ origin_installation_id: 'other' }]; },
  ]) {
    const state = records(); mutate(state);
    assert.equal(canSubmitCompleteBackup(state), false);
  }
  for (const kind of ['unavailable', 'error', 'loading']) assert.equal(canSubmitCompleteBackup({ kind }), false);
});

test('a full overview retains its existing enabled and same configuration checks', () => {
  const state = { kind: 'ready', data: {
    config: { active: true, origin_installation_id: 'original', version: 3, effective_enabled: true },
    overview: { origin_installation_id: 'original', config_version: 3, effective_enabled: true },
  } };
  assert.equal(canSubmitCompleteBackup(state), true);
  for (const mutate of [
    s => { s.data.config.active = false; },
    s => { s.data.config.version = 4; },
    s => { s.data.config.origin_installation_id = 'other'; },
    s => { s.data.config.effective_enabled = false; },
    s => { s.data.overview.effective_enabled = false; },
  ]) {
    const copy = structuredClone(state); mutate(copy);
    assert.equal(canSubmitCompleteBackup(copy), false);
  }
});
