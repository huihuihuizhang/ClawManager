import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { scanCreateStatements, scanRepositoryAlters, buildReport } from './system-backup-schema-inventory.mjs';
import { buildRegistry, strictBlockers } from './system-backup-contract-check.mjs';

test('inventory excludes Go test fixture DDL but still detects production DDL', () => {
  const directory = mkdtempSync(join(tmpdir(), 'b-schema-source-'));
  try {
    writeFileSync(join(directory, 'fixture_test.go'), 'package repository\nconst fixture = `\nCREATE TABLE test_only (id INT);\nALTER TABLE test_only ADD COLUMN value INT;\n`\n');
    writeFileSync(join(directory, 'production.go'), 'package repository\nconst ddl = `\nCREATE TABLE real_runtime (id INT);\nALTER TABLE real_runtime ADD COLUMN value INT;\n`\n');
    writeFileSync(join(directory, 'production_linux.go'), 'package repository\nconst ddl = `\nCREATE TABLE linux_runtime (id INT);\nALTER TABLE linux_runtime ADD COLUMN value INT;\n`\n');
    assert.deepEqual([...scanCreateStatements(directory, '.go').keys()].sort(), ['table:linux_runtime', 'table:real_runtime']);
    assert.deepEqual([...scanRepositoryAlters(directory).keys()].sort(), ['linux_runtime', 'real_runtime']);
    // The exclusion is Go-specific: a migration filename ending in _test.sql
    // still constitutes an embedded schema source and must not disappear.
    writeFileSync(join(directory, '001_test.sql'), 'CREATE TABLE migrated (id INT);\n');
    assert.deepEqual([...scanCreateStatements(directory, '.sql').keys()], ['table:migrated']);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('current repository test ALTER fixtures do not claim runtime DDL', () => {
  const report = buildReport();
  assert.equal(report.summary.repository_runtime_alter, 0);
  assert.equal(report.summary.repository_runtime_create, 0);
  for (const object of report.objects) {
    assert.ok([...object.repository_create_sources, ...object.repository_alter_sources].every(path => !path.endsWith('_test.go')));
  }
});

test('new ownership routing stays pending and cannot grant P0 capture', () => {
  const groups = [
    ['A', 'users', ['northbound_owner_records']],
    ['A', 'ai_gateway', ['gateway_keys', 'gateway_key_budget_reservations', 'gateway_key_budget_ledger', 'llm_model_user_grants', 'routing_classifier_settings', 'gateway_image_artifacts', 'gateway_image_jobs']],
    ['B', 'instances', ['gateway_runtime_tasks', 'gateway_runtime_task_models', 'gateway_runtime_protocols', 'gateway_runtime_maintenance', 'gateway_runtime_upgrades', 'gateway_runtime_upgrade_stops', 'instance_lifecycle_scheduler', 'instance_lifecycle_manual_guards', 'instance_lifecycle_batches', 'instance_lifecycle_batch_items', 'instance_lifecycle_batch_attempts', 'runtime_rollout_checkpoints', 'instance_workspace_write_intents']],
    ['C', 'teams', ['team_workspace_file_audits']],
  ];
  const inventory = buildReport();
  const registry = buildRegistry();
  const blockers = strictBlockers(registry, { artifacts: [] });
  let count = 0;
  for (const [owner, category, names] of groups) for (const name of names) {
    const observed = inventory.objects.find(object => object.name === name);
    assert.equal(observed?.owner, owner, name);
    assert.equal(observed.category, category);
    const policy = registry.objects.find(object => object.name === name);
    assert.equal(policy?.decision_status, 'pending_owner_review', name);
    for (const field of ['data_classification', 'backup_strategy', 'restore_strategy', 'normalizer_id', 'verifier_id']) assert.equal(policy[field], null, `${name}.${field}`);
    assert.deepEqual(policy.approved_cross_reviewers, []);
    assert.ok(blockers.policy_pending.includes(`table:${name}`));
    count++;
  }
  assert.equal(count, 22);
  assert.equal(registry.contract_status, 'draft');
  assert.equal(registry.summary.policy_pending, 55);
  assert.equal(blockers.schema_hash_pending, true);
});
